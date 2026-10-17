"""Tests for main.py's _print_message() - the only unit-testable piece of
the CLI entry point (main() itself just loops over the real SDK's query(),
not worth mocking a whole async generator to re-verify that). Previously
0% coverage, like mcp_server.py before today."""
from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, ToolUseBlock

from main import _print_message


def _result_message(**overrides):
    defaults = dict(
        subtype="success",
        duration_ms=1234,
        duration_api_ms=1000,
        is_error=False,
        num_turns=1,
        session_id="abc",
        total_cost_usd=0.012,
    )
    defaults.update(overrides)
    return ResultMessage(**defaults)


def test_assistant_text_block_is_printed(capsys):
    _print_message(AssistantMessage(content=[TextBlock(text="hello there")], model="sonnet"))
    assert "hello there" in capsys.readouterr().out


def test_assistant_empty_text_block_prints_nothing(capsys):
    _print_message(AssistantMessage(content=[TextBlock(text="")], model="sonnet"))
    assert capsys.readouterr().out == ""


def test_tool_use_block_strips_mcp_namespace_prefix(capsys):
    block = ToolUseBlock(id="1", name="mcp__websec__analyze_webpage", input={"url": "https://example.com"})
    _print_message(AssistantMessage(content=[block], model="sonnet"))
    out = capsys.readouterr().out
    assert "🔧 analyze_webpage(" in out
    assert "mcp__websec__" not in out
    assert "url='https://example.com'" in out


def test_tool_use_block_without_namespace_prefix_uses_name_as_is(capsys):
    block = ToolUseBlock(id="1", name="plain_tool", input={})
    _print_message(AssistantMessage(content=[block], model="sonnet"))
    assert "🔧 plain_tool()" in capsys.readouterr().out


def test_result_message_prints_duration_and_cost(capsys):
    _print_message(_result_message(duration_ms=2500, total_cost_usd=0.042))
    out = capsys.readouterr().out
    assert "2.5s" in out
    assert "$0.042" in out


def test_result_message_with_no_cost_does_not_crash(capsys):
    # total_cost_usd is Optional[float] on the real SDK type - a result
    # with no cost info (e.g. an error before any model call) must not
    # crash this formatter.
    _print_message(_result_message(total_cost_usd=None))
    out = capsys.readouterr().out
    assert "cost unknown" in out


def test_unhandled_message_type_prints_nothing(capsys):
    _print_message(object())
    assert capsys.readouterr().out == ""
