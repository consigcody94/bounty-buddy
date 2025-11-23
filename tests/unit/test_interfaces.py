"""
Unit tests for core interfaces and data structures
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from iothackbot.core.interfaces import (
    ToolConfig,
    ToolResult,
    ToolInterface,
    OutputFormatter,
    ConfigBuilder
)


class TestToolConfig:
    """Test ToolConfig dataclass"""

    def test_tool_config_creation(self):
        """Test creating a ToolConfig instance"""
        config = ToolConfig(
            input_paths=["/test/path"],
            output_format="json",
            verbose=True
        )
        assert config.input_paths == ["/test/path"]
        assert config.output_format == "json"
        assert config.verbose is True

    def test_tool_config_defaults(self):
        """Test ToolConfig default values"""
        config = ToolConfig(input_paths=["/test"])
        assert config.output_format == "text"
        assert config.verbose is False
        assert config.timeout is None
        assert config.custom_args == {}

    def test_tool_config_backward_compatibility(self):
        """Test backward compatibility input_path property"""
        config = ToolConfig(input_paths=["/first/path", "/second/path"])
        assert config.input_path == "/first/path"

    def test_tool_config_empty_paths(self):
        """Test input_path property with empty paths list"""
        config = ToolConfig(input_paths=[])
        assert config.input_path == ""


class TestToolResult:
    """Test ToolResult dataclass"""

    def test_tool_result_creation(self):
        """Test creating a ToolResult instance"""
        result = ToolResult(
            success=True,
            data={"key": "value"},
            errors=[],
            metadata={"tool": "test"},
            execution_time=1.5
        )
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.errors == []
        assert result.metadata == {"tool": "test"}
        assert result.execution_time == 1.5

    def test_tool_result_defaults(self):
        """Test ToolResult default values"""
        result = ToolResult(success=False)
        assert result.success is False
        assert result.data is None
        assert result.errors == []
        assert result.metadata == {}
        assert result.execution_time == 0.0

    def test_tool_result_with_errors(self):
        """Test ToolResult with error messages"""
        errors = ["Error 1", "Error 2"]
        result = ToolResult(success=False, errors=errors)
        assert result.success is False
        assert len(result.errors) == 2
        assert "Error 1" in result.errors


class TestOutputFormatter:
    """Test OutputFormatter class"""

    def test_format_json(self):
        """Test JSON formatting"""
        result = ToolResult(success=True, data={"test": "value"})
        formatter = OutputFormatter()
        output = formatter.format_result(result, "json")
        assert '"success": true' in output
        assert '"test": "value"' in output

    def test_format_text_success(self):
        """Test text formatting for successful result"""
        result = ToolResult(success=True, execution_time=1.23)
        formatter = OutputFormatter()
        output = formatter.format_result(result, "text")
        assert "SUCCESS" in output
        assert "1.23s" in output

    def test_format_text_failure(self):
        """Test text formatting for failed result"""
        result = ToolResult(success=False, errors=["Test error"])
        formatter = OutputFormatter()
        output = formatter.format_result(result, "text")
        assert "FAILED" in output
        assert "Test error" in output

    def test_format_quiet_success(self):
        """Test quiet formatting for successful result"""
        result = ToolResult(success=True)
        formatter = OutputFormatter()
        output = formatter.format_result(result, "quiet")
        assert output == ""

    def test_format_quiet_failure(self):
        """Test quiet formatting for failed result"""
        result = ToolResult(success=False, errors=["Error 1", "Error 2"])
        formatter = OutputFormatter()
        output = formatter.format_result(result, "quiet")
        assert "Error 1" in output
        assert "Error 2" in output

    def test_invalid_format_type(self):
        """Test handling of invalid format type"""
        result = ToolResult(success=True)
        formatter = OutputFormatter()
        with pytest.raises(ValueError):
            formatter.format_result(result, "invalid")


class MockArgs:
    """Mock argparse args for testing ConfigBuilder"""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestConfigBuilder:
    """Test ConfigBuilder class"""

    def test_from_args_basic(self):
        """Test building config from basic args"""
        args = MockArgs(
            path="/test/path",
            format="json",
            verbose=True
        )
        config = ConfigBuilder.from_args(args, "test_tool")
        assert config.input_paths == ["/test/path"]
        assert config.output_format == "json"
        assert config.verbose is True

    def test_from_args_multiple_paths(self):
        """Test building config from args with multiple paths"""
        args = MockArgs(
            paths=["/path1", "/path2"],
            format="text",
            verbose=False
        )
        config = ConfigBuilder.from_args(args, "test_tool")
        assert config.input_paths == ["/path1", "/path2"]

    def test_from_args_custom_args(self):
        """Test building config with custom arguments"""
        args = MockArgs(
            target="192.168.1.1",
            format="text",
            verbose=False,
            threads=10,
            extract=True
        )
        config = ConfigBuilder.from_args(args, "test_tool")
        assert config.input_paths == ["192.168.1.1"]
        assert config.custom_args.get("threads") == 10
        assert config.custom_args.get("extract") is True

    def test_from_args_timeout(self):
        """Test building config with timeout"""
        args = MockArgs(
            input="/test",
            timeout=30
        )
        config = ConfigBuilder.from_args(args, "test_tool")
        assert config.timeout == 30

    def test_from_dict(self):
        """Test building config from dictionary"""
        data = {
            "input_paths": ["/test"],
            "output_format": "json",
            "verbose": True,
            "custom_args": {"key": "value"}
        }
        config = ConfigBuilder.from_dict(data)
        assert config.input_paths == ["/test"]
        assert config.output_format == "json"
        assert config.verbose is True
        assert config.custom_args == {"key": "value"}


class MockTool(ToolInterface):
    """Mock tool for testing ToolInterface"""

    @property
    def name(self) -> str:
        return "mock_tool"

    @property
    def description(self) -> str:
        return "A mock tool for testing"

    def run(self, config: ToolConfig) -> ToolResult:
        return ToolResult(success=True, data={"mock": "data"})


class TestToolInterface:
    """Test ToolInterface abstract base class"""

    def test_tool_implementation(self):
        """Test implementing ToolInterface"""
        tool = MockTool()
        assert tool.name == "mock_tool"
        assert tool.description == "A mock tool for testing"

    def test_tool_run(self):
        """Test running a tool"""
        tool = MockTool()
        config = ToolConfig(input_paths=["/test"])
        result = tool.run(config)
        assert result.success is True
        assert result.data == {"mock": "data"}

    def test_tool_interface_abstract(self):
        """Test that ToolInterface cannot be instantiated directly"""
        with pytest.raises(TypeError):
            ToolInterface()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
