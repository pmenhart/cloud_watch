defmodule CloudWatch.InputLogEvent do
  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

  @enforce_keys  [:message, :timestamp]
  defstruct [:message, :timestamp]

  def convert_timestamp(timestamp) do
    {{years, months, days}, {hours, minutes, seconds, milliseconds}} = timestamp
    :calendar.datetime_to_gregorian_seconds({{years, months, days}, {hours, minutes, seconds}})
    |> Kernel.-(@epoch)
    |> Kernel.*(1000)
    |> Kernel.+(milliseconds)
  end

  defimpl Poison.Encoder do
    def encode(%{message: message, timestamp: timestamp}, options) do
      %{message: message, timestamp: CloudWatch.InputLogEvent.convert_timestamp(timestamp)}
      |> Poison.Encoder.encode(options)
      |> IO.chardata_to_string
    end
  end

end
