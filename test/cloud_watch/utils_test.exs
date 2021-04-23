defmodule CloudWatch.UtilsTest do
  alias CloudWatch.Utils

  use ExUnit.Case

  test "convert_timestamp" do
    timestamp = Utils.convert_timestamp({{2016, 10, 26}, {12, 8, 34, 220}})
    assert timestamp == 1477483714220
  end
end
