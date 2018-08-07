defmodule CloudWatch do
  @behaviour :gen_event
  @default_endpoint "amazonaws.com"
  @default_format "$metadata[$level] $message\n"
  @default_level :info
  @default_max_buffer_size 10_485
  @default_max_timeout 60_000

  alias CloudWatch.InputLogEvent
  alias CloudWatch.AwsProxy

  @spec init(module()) :: {:ok, term()} | {:error, term()}
  def init(__MODULE__) do
    {:ok, _} = Application.ensure_all_started(:hackney)

    state = configure([])

    # If AWS keys are not defined statically, get them from the instance metadata.
    # This may fail while the instance is starting up, so retry quickly.
    # Otherwise refresh every 10 minutes, as the keys expire periodically.
    unless state.access_key_id do
      if state.client do
        Process.send_after(self(), :refresh_creds, 300_000)
      else
        Process.send_after(self(), :refresh_creds, 200)
      end
    end

    Process.send_after(self(), :flush, state.max_timeout)
    {:ok, state}
  end

  def handle_call({:configure, opts}, _) do
    Application.put_env(:logger, __MODULE__, opts)
    {:ok, :ok, configure(opts)}
  end

  def handle_call(_, state) do
    {:ok, :ok, state}
  end

  def handle_event({level, _gl, {Logger, msg, ts, md}}, state) do
    case Logger.compare_levels(level, state.level) do
      :lt -> {:ok, state}
      _ ->
        %{buffer: buffer, buffer_size: buffer_size} = state
        message = state.format
        |> Logger.Formatter.format(level, msg, ts, md)
        |> IO.chardata_to_string
        buffer = List.insert_at(buffer, -1, %InputLogEvent{message: message, timestamp: ts})
        state
        |> Map.merge(%{buffer: buffer, buffer_size: buffer_size + byte_size(message) + 26})
        |> flush()
    end
  end

  def handle_event(:flush, state) do
    {:ok, %{state | buffer: [], buffer_size: 0}}
  end

  def handle_info(:flush, state) do
    {:ok, flushed_state} = flush(state, force: true)
    Process.send_after(self(), :flush, state.max_timeout)
    {:ok, flushed_state}
  end

  def handle_info(:refresh_creds, state) do
    state = configure_aws(state)
    if state.client do
      Process.send_after(self(), :refresh_creds, 300_000)
    else
      Process.send_after(self(), :refresh_creds, 200)
    end
    {:ok, state}
  end

  def handle_info(_msg, state) do
    {:ok, state}
  end

  def code_change(_previous_version_number, state, _extra) do
    {:ok, state}
  end

  def terminate(_reason, _state) do
    :ok
  end

  @spec configure(Keyword.t) :: Map.t
  def configure(opts) do
    env = Application.get_env(:logger, __MODULE__, [])
    opts = Keyword.merge(env, opts)

    state = %{
      access_key_id: opts[:access_key_id],
      secret_access_key: opts[:secret_access_key],
      region: opts[:region],
      endpoint: opts[:endpoint],
      client: nil,
      buffer: [], buffer_size: 0,
      level: opts[:level] || @default_level,
      format: Logger.Formatter.compile(opts[:format] || @default_format),
      log_group_name: opts[:log_group_name],
      log_stream_name: opts[:log_stream_name],
      max_buffer_size: opts[:max_buffer_size] || @default_max_buffer_size,
      max_timeout: opts[:max_timeout] || @default_max_timeout,
      sequence_token: nil, flushed_at: nil
    }

    if state.access_key_id do
      %{state | client: AwsProxy.client(state.access_key_id, state.secret_access_key, state.region, state.endpoint)}
    else
      configure_aws(state)
    end
  end

  def configure_aws(state) do
    case System.get_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") do
      nil ->
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        case get_metadata("http://169.254.169.254/latest/meta-data/iam/security-credentials/") do
          {:ok, ""} ->
            state
          {:ok, role} ->
            {:ok, json} = get_metadata("http://169.254.169.254/latest/meta-data/iam/security-credentials/" <> role)
            {:ok, creds} = Poison.decode(json)
            access_key_id = Map.get(creds, "AccessKeyId")
            secret_access_key = Map.get(creds, "SecretAccessKey")
            region = state.region || metadata_region()
            endpoint = state.endpoint || metadata_endpoint() || @default_endpoint
            client = AwsProxy.client(access_key_id, secret_access_key, region, endpoint)

            log_stream_name = state.log_stream_name || metadata_instance_id()

            %{state | client: client, log_stream_name: log_stream_name}
          _ ->
            state
        end
      uri ->
        # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
        case get_metadata("http://169.254.170.2" <> uri) do
          {:ok, json} ->
            {:ok, creds} = Poison.decode(json)
            access_key_id = Map.get(creds, "AccessKeyId")
            secret_access_key = Map.get(creds, "SecretAccessKey")
            region = state.region
            endpoint = state.endpoint || @default_endpoint
            client = AwsProxy.client(access_key_id, secret_access_key, region, endpoint)
            %{state | client: client}
          _ ->
            state
        end
    end
  end

  defp flush(state, opts \\ [force: false])

  defp flush(%{buffer: buffer, buffer_size: buffer_size, max_buffer_size: max_buffer_size} = state, [force: false])
    when buffer_size < max_buffer_size and length(buffer) < 10_000 do
      {:ok, state}
  end

  defp flush(%{buffer: []} = state, _opts), do: {:ok, state}

  defp flush(%{client: nil} = state, _opts), do: {:ok, state}

  defp flush(state, opts) do
    case AwsProxy.put_log_events(state.client, %{logEvents: Enum.sort_by(state.buffer, &(&1.timestamp)),
      logGroupName: state.log_group_name, logStreamName: state.log_stream_name, sequenceToken: state.sequence_token}) do
        {:ok, %{"nextSequenceToken" => next_sequence_token}, _} ->
          {:ok, Map.merge(state, %{buffer: [], buffer_size: 0, sequence_token: next_sequence_token})}
        {:error, {"DataAlreadyAcceptedException", "The given batch of log events has already been accepted. The next batch can be sent with sequenceToken: " <> next_sequence_token}} ->
          state
          |> Map.put(:sequence_token, next_sequence_token)
          |> flush(opts)
        {:error, {"InvalidSequenceTokenException", "The given sequenceToken is invalid. The next expected sequenceToken is: " <> next_sequence_token}} ->
          state
          |> Map.put(:sequence_token, next_sequence_token)
          |> flush(opts)
        {:error, {"ResourceNotFoundException", "The specified log group does not exist."}} ->
          AwsProxy.create_log_group(state.client, %{logGroupName: state.log_group_name})
          AwsProxy.create_log_stream(state.client, %{logGroupName: state.log_group_name,
            logStreamName: state.log_stream_name})
          flush(state, opts)
        {:error, {"ResourceNotFoundException", "The specified log stream does not exist."}} ->
          AwsProxy.create_log_stream(state.client, %{logGroupName: state.log_group_name,
            logStreamName: state.log_stream_name})
          flush(state, opts)
        {:error, %HTTPoison.Error{id: nil, reason: reason}} when reason in [:closed, :connect_timeout, :timeout] ->
          state
          |> flush(opts)
    end
  end

  def get_metadata(url) do
    case :hackney.request(:get, url, [], "", []) do
      {:ok, 200, _resp_headers, client_ref} ->
        :hackney.body(client_ref)
      _ ->
        nil
    end
    # case HTTPoison.get(url) do
    #   {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
    #     {:ok, body}
    #   _ ->
    #     nil
    # end
  end

  def get_metadata!(url) do
    case :hackney.request(:get, url, [], "", []) do
      {:ok, 200, _resp_headers, client_ref} ->
        {:ok, body} = :hackney.body(client_ref)
        body
      _ ->
        nil
    end
    # case HTTPoison.get(url) do
    #   {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
    #     body
    #   _ ->
    #     nil
    # end
  end

  def metadata_endpoint do
    get_metadata!("http://169.254.169.254/latest/meta-data/services/domain")
  end

  def metadata_instance_id do
    get_metadata!("http://169.254.169.254/latest/meta-data/instance-id")
  end

  def metadata_region do
    url = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
    case :hackney.request(:get, url, [], "", []) do
      {:ok, 200, _resp_headers, client_ref} ->
        {:ok, body} = :hackney.body(client_ref)
        String.slice(body, Range.new(0, -2))
      _ ->
        nil
    end
    # case HTTPoison.get(url) do
    #   {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
    #     String.slice(body, Range.new(0, -2))
    #   _ ->
    #     nil
    # end
  end

end
