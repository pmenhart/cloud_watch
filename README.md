# CloudWatch

`cloud_watch` is a logger backend for Elixir that puts log events on Amazon
CloudWatch.

## Installation

Add `cloud_watch` and `aws` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [{:cloud_watch, "~> 0.3.0"},
     {:aws, "~> 0.5.0"}]
  end
  ```

Ensure `cloud_watch` is started before your application:

  ```elixir
  def application do
    [applications: [:cloud_watch]]
  end
  ```

## Configuration

Add the backend to `config.exs`:

  ```elixir
  config :logger,
    backends: [:console, CloudWatch],
    utc_log: true
  ```

Following is a full example with the default values:

  ```elixir
  config :logger, CloudWatch,
    access_key_id: "AKIAIOSFODNN7EXAMPLE",
    secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "eu-west-1",
    endpoint: "amazonaws.com",
    log_group_name: "api",
    log_stream_name: "production",
    max_buffer_size: 10_485,
    max_timeout: 60_000
  ```

CloudWatch flushes the buffer when it has collected `max_buffer_size` bytes of
messages or `max_timeout` milliseconds have elapsed. `max_buffer_size` can be
anything up to a maximum of 1,048,576 bytes. If omitted, it will default to
10,485 bytes.

CloudWatch supports getting AWS credentials and other defaults from
[EC2 instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)

In that case, a minimal configuration is:

  ```elixir
  config :logger, CloudWatch,
    log_group_name: "api"
  ```

`log_stream_name` defaults to the instance id.

## Alternative AWS client library: ExAws

Default installation instructions assume that the [AWS](https://github.com/jkakar/aws-elixir) Elixir library will be used. If you have to (or prefer to) use [ExAws](https://github.com/ex-aws/ex_aws) instead, solution is really simple:
Replace `aws` with `ex-aws` in your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [{:cloud_watch, "~> 0.2.8"},
    {:ex_aws, "~> 2.0"}]
  end
  ```

CloudWatch switches to ExAws automagically based on its presence at compile time. Just make sure that `aws` is not added as a dependency of another application in an umbrella project.


Note that `ExAws` resolves AWS credentials through its own configuration. As a consequence, following keys in CloudWatch configuration are not used:
- `access_key_id`
- `secret_access_key`
- `region`
- `endpoint`

### ExAws requires valid AWS keys in order to work properly
This statement seems obvious, but it may be useful to understand
how the system behaves when the configuration is not right:

Logger uses a build-in supervisor that is well capable of handling most problems.
For example, network connection issues or invalid AWS keys seems to be treated well,
with meaningful messages logged to other backend (console or file).
If the error is transient, messages are sent to CloudWatch logs after recovery.

When ExAws cannot find the AWS secret key through the credential resolution process
(see ExAws documentation for details), the initial error message makes sense:
```
** (EXIT) an exception was raised:
           ** (RuntimeError) Instance Meta Error: {:error, %{reason: :connect_timeout}}

   You tried to access the AWS EC2 instance meta, but it could not be reached.
   This happens most often when trying to access it from your local computer,
   which happens when environment variables are not set correctly prompting
   ExAws to fallback to the Instance Meta.

   Please check your key config and make sure they're configured correctly
```
However, you'll experience a flood of errors and sasl reports,
as both Logger and ExAws supervisors are busy restarting children over and over.
Finding the root cause is a challenge, as the subsequent error messages are misleading:
":ehostdown", "argument error", ":badarg, {:ets, :lookup}".

Missing AWS keys is a permanent error (unless the keys can magically show up in your app),
hence should be caught early during deployment.
Our advice is to add an AWS call to the application start logic.
This can be an application specific request (especially when the application talks
to AWS for other services), or just a dummy AWS call.
Alternatively, the ExAws configuration can be tested without calling AWS, e.g.
```elixir
ExAws.Auth.validate_config(ExAws.Config.new(:logs, []))
```
