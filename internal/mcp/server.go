package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Server implements the MCP protocol over stdio.
type Server struct {
	tools     map[string]MCPTool
	resources map[string]MCPResource
	reader    *bufio.Reader
	writer    io.Writer
}

// MCPTool is an MCP-callable tool.
type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Handler     func(args json.RawMessage) (string, error)
}

// MCPResource is an MCP-readable resource.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
	Handler     func() (string, error)
}

// NewServer creates a new MCP server.
func NewServer() *Server {
	return &Server{
		tools:     make(map[string]MCPTool),
		resources: make(map[string]MCPResource),
		reader:    bufio.NewReader(os.Stdin),
		writer:    os.Stdout,
	}
}

// RegisterTool adds a tool to the MCP server.
func (s *Server) RegisterTool(tool MCPTool) {
	s.tools[tool.Name] = tool
}

// RegisterResource adds a resource to the MCP server.
func (s *Server) RegisterResource(resource MCPResource) {
	s.resources[resource.URI] = resource
}

// Serve starts the MCP server loop (stdio transport).
func (s *Server) Serve() error {
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		s.handleRequest(req)
	}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleRequest(req jsonRPCRequest) {
	switch req.Method {
	case "initialize":
		s.sendResult(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "pentestswarm",
				"version": "1.0.0",
			},
		})

	case "tools/list":
		var toolList []map[string]any
		for _, t := range s.tools {
			toolList = append(toolList, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": json.RawMessage(t.InputSchema),
			})
		}
		s.sendResult(req.ID, map[string]any{"tools": toolList})

	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(req.ID, -32602, "Invalid params")
			return
		}

		tool, ok := s.tools[params.Name]
		if !ok {
			s.sendError(req.ID, -32601, fmt.Sprintf("Tool %q not found", params.Name))
			return
		}

		result, err := tool.Handler(params.Arguments)
		if err != nil {
			s.sendResult(req.ID, map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "Error: " + err.Error()},
				},
				"isError": true,
			})
			return
		}

		s.sendResult(req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": result},
			},
		})

	case "resources/list":
		var resourceList []map[string]any
		for _, r := range s.resources {
			resourceList = append(resourceList, map[string]any{
				"uri":         r.URI,
				"name":        r.Name,
				"description": r.Description,
				"mimeType":    r.MimeType,
			})
		}
		s.sendResult(req.ID, map[string]any{"resources": resourceList})

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(req.ID, -32602, "Invalid params")
			return
		}

		resource, ok := s.resources[params.URI]
		if !ok {
			s.sendError(req.ID, -32601, fmt.Sprintf("Resource %q not found", params.URI))
			return
		}

		content, err := resource.Handler()
		if err != nil {
			s.sendError(req.ID, -32603, err.Error())
			return
		}

		s.sendResult(req.ID, map[string]any{
			"contents": []map[string]any{
				{"uri": params.URI, "mimeType": resource.MimeType, "text": content},
			},
		})

	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method %q not found", req.Method))
	}
}

func (s *Server) sendResult(id any, result any) {
	resp := jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.writer, "%s\n", data)
}

func (s *Server) sendError(id any, code int, message string) {
	resp := jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &jsonRPCError{Code: code, Message: message}}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.writer, "%s\n", data)
}
