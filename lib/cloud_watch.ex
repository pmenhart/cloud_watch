defmodule CloudWatch do
  @behaviour :gen_event
  @default_endpoint "amazonaws.com"
  @default_format "$metadata[$level] $message\n"
  @default_level :info
  @default_max_buffer_size 10_485
  @default_max_timeout 60_000

  alias CloudWatch.InputLogEvent
  alias CloudWatch.AwsProxy

  def init(_) do
    state = configure(Application.get_env(:logger, CloudWatch, []))
    Process.send_after(self(), :flush, state.max_timeout)
    {:ok, state}
  end

  def handle_call({:configure, opts}, _) do
    {:ok, :ok, configure(opts)}
  end

  def handle_call(_, state) do
    {:ok, :ok, state}
  end

  def handle_event({level, _gl, {Logger, msg, ts, md}}, state) do
    case Logger.compare_levels(level, state.level) do
      :lt -> {:ok, state}
      _ ->
        state = add_message(state, level, msg, ts, md)
        flush(state)
    end
  end

  def handle_event(:flush, state) do
    {:ok, purge_buffer(state)}
  end

  def handle_info(:flush, state) do
    {:ok, flushed_state} = flush(state, force: true)
    Process.send_after(self(), :flush, state.max_timeout)
    {:ok, flushed_state}
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

  defp configure(opts) do
    opts = Keyword.merge(Application.get_env(:logger, CloudWatch, []), opts)
    format = Logger.Formatter.compile(Keyword.get(opts, :format, @default_format))
    level = Keyword.get(opts, :level, @default_level)
    log_group_name = Keyword.get(opts, :log_group_name)
    log_stream_name = Keyword.get(opts, :log_stream_name)
    max_buffer_size = Keyword.get(opts, :max_buffer_size, @default_max_buffer_size)
    max_timeout = Keyword.get(opts, :max_timeout, @default_max_timeout)
    purge_buffer_if_throttled? = Keyword.get(opts, :purge_buffer_if_throttled, false) # see "ThrottlingException"

    # AWS configuration, only if needed by the AWS library
    region = Keyword.get(opts, :region)
    access_key_id = Keyword.get(opts, :access_key_id)
    endpoint = Keyword.get(opts, :endpoint, @default_endpoint)
    secret_access_key = Keyword.get(opts, :secret_access_key)
    client = AwsProxy.client(access_key_id, secret_access_key, region, endpoint)
    %{
      buffer: [],
      buffer_size: 0,
      client: client,
      format: format,
      level: level,
      log_group_name: log_group_name,
      log_stream_name: log_stream_name,
      max_buffer_size: max_buffer_size,
      max_timeout: max_timeout,
      purge_buffer_if_throttled: purge_buffer_if_throttled?,
      sequence_token: nil,
      flushed_at: nil
    }
  end

  defp purge_buffer(state) do
    %{state | buffer: [], buffer_size: 0}
  end

  defp add_message(%{buffer: buffer, buffer_size: buffer_size} = state, level, msg, ts, md) do
    message = state.format
              |> Logger.Formatter.format(level, msg, ts, md)
              |> IO.chardata_to_string
    buffer = List.insert_at(buffer, -1, %InputLogEvent{message: message, timestamp: ts})
    %{state | buffer: buffer, buffer_size: buffer_size + byte_size(message) + 26}
  end

  defp flush(_state, _opts \\ [force: false])

  defp flush(%{buffer: buffer, buffer_size: buffer_size, max_buffer_size: max_buffer_size} = state, [force: false])
    when buffer_size < max_buffer_size and length(buffer) < 10_000 do
      {:ok, state}
  end

  defp flush(%{buffer: []} = state, _opts), do: {:ok, state}

  defp flush(state, opts) do
    # Log names could change between calls, but has to remain stable inside the method `do_flush/4`
    log_group_name = resolve_name(state.log_group_name)
    log_stream_name = resolve_name(state.log_stream_name)
    do_flush(state, opts, log_group_name, log_stream_name)
  end

  defp do_flush(state, opts, log_group_name, log_stream_name) do
    events = %{logEvents: Enum.sort_by(state.buffer, &(&1.timestamp)),
        logGroupName: log_group_name, logStreamName: log_stream_name, sequenceToken: state.sequence_token}
    case AwsProxy.put_log_events(state.client, events) do
      {:ok, %{"nextSequenceToken" => next_sequence_token}, _} ->
        msg_count = length(state.buffer)
        {:ok, state |> purge_buffer() |> Map.put(:sequence_token, next_sequence_token)
              |> add_internal_info("CloudWatch Log flushed buffer (#{inspect msg_count} messages)")}
      {:error, {"DataAlreadyAcceptedException", "The given batch of log events has already been accepted. The next batch can be sent with sequenceToken: " <> next_sequence_token}} ->
        state
        |> Map.put(:sequence_token, next_sequence_token)
        |> do_flush(opts, log_group_name, log_stream_name)
      {:error, {"InvalidSequenceTokenException", "The given sequenceToken is invalid. The next expected sequenceToken is: " <> next_sequence_token}} ->
        state
        |> Map.put(:sequence_token, next_sequence_token)
        |> do_flush(opts, log_group_name, log_stream_name)
      {:error, {"ResourceNotFoundException", "The specified log group does not exist."}} ->
        {:ok, _, _} = AwsProxy.create_log_group(state.client, %{logGroupName: log_group_name})
        {:ok, _, _} = AwsProxy.create_log_stream(
          state.client,
          %{logGroupName: log_group_name, logStreamName: log_stream_name}
        )
        do_flush(state, opts, log_group_name, log_stream_name)
      {:error, {"ResourceNotFoundException", "The specified log stream does not exist."}} ->
        {:ok, _, _} = AwsProxy.create_log_stream(
          state.client,
          %{logGroupName: log_group_name, logStreamName: log_stream_name}
        )
        do_flush(state, opts, log_group_name, log_stream_name)
      {:error, {"ThrottlingException", "Rate exceeded"}} ->
        # AWS limit is 5 requests per second per log stream. We are supposed to re-try after a delay
        if state.purge_buffer_if_throttled do
          # Safe option: delay the transfer by removing all messages from the buffer (some messages will be lost!).
          lost_msg_count = length(state.buffer)
          {
            :ok,
            state
            |> purge_buffer()
            |> add_internal_error("CloudWatch Log ThrottlingException: #{inspect lost_msg_count} messages were lost!}")
          }
        else
          # Sleeping here is a quick and dirty hack with possible unwanted consequences
          # Better approach: introduce a blackout period. Start removing old logs if buffer size exceeded 1 MB during blackout
          state = state |> add_internal_error("CloudWatch Log ThrottlingException: delaying transfer")
          Process.sleep(500)
          flush(state, opts)
         end
      {:error, {"ExpiredTokenException", _}} ->
        # aws-elixir may require restarting of state.client; ex_aws handles expired tokens internally
        flush(state, opts)
      {:error, %HTTPoison.Error{id: nil, reason: reason}} when reason in [:connect_timeout] ->
        state = state |> add_internal_error("CloudWatch Log connect timeout")
        Process.sleep(500)
        flush(state, opts)
      {:error, %HTTPoison.Error{id: nil, reason: reason}} when reason in [:closed, :timeout] ->
        do_flush(state, opts, log_group_name, log_stream_name)
    end
  end

  defp add_internal_error(state, msg) do
    add_internal_message(state, :error, msg)
  end

  defp add_internal_info(state, msg) do
    add_internal_message(state, :info, msg)
  end

  defp add_internal_message(state, level, msg) do
    utc_log? = Application.get_env(:logger, :utc_log, false)
    state
    |> add_message(
         level,
         msg,
         Logger.Utils.timestamp(utc_log?),
         Logger.metadata()
       )
  end

  # Apply a MFA tuple (Module, Function, Attributes) to obtain the name. Function must return a string
  defp resolve_name({m, f, a}) do
    :erlang.apply(m, f, a)
  end
  # Use the name directly
  defp resolve_name(name) do
    name
  end

end
