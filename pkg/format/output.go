package format

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/alexeyco/simpletable"
	"github.com/ghodss/yaml"
	"github.com/hako/durafmt"
	"github.com/icza/gox/mathx"
	"github.com/spyzhov/ajson"
)

var outputWriter io.Writer

func init() {
	ajson.AddFunction("seconds_pretty", func(node *ajson.Node) (result *ajson.Node, err error) {
		var seconds int
		if node.IsString() {
			seconds, err = strconv.Atoi(node.MustString())
			if err != nil {
				return node, err
			}
		} else {
			return node, fmt.Errorf("seconds_pretty: unknown data type %d", node.Type())
		}

		fmtTime := durafmt.Parse(time.Duration(seconds) * time.Second)

		return ajson.StringNode("", fmtTime.LimitFirstN(2).String()), err
	})

	// based on the pg_size_pretty function in Postgres
	ajson.AddFunction("size_pretty", func(node *ajson.Node) (result *ajson.Node, err error) {
		var size int
		if node.IsString() {
			size, err = strconv.Atoi(node.MustString())
			if err != nil {
				return node, err
			}
		} else if node.IsNumeric() {
			size = int(node.MustNumeric())
		} else {
			return node, fmt.Errorf("size_pretty: unknown data type %d", node.Type())
		}

		limit := 10 * 1024

		if mathx.AbsInt(size) < limit {
			result = ajson.StringNode("", fmt.Sprintf("%d B", size))
		} else {
			size /= 1 << 10
			if size < limit {
				result = ajson.StringNode("", fmt.Sprintf("%d kB", size))
			} else {
				size /= 1 << 10
				if size < limit {
					result = ajson.StringNode("", fmt.Sprintf("%d MB", size))
				} else {
					size /= 1 << 10
					if size < limit {
						result = ajson.StringNode("", fmt.Sprintf("%d GB", size))
					} else {
						size /= 1 << 10
						result = ajson.StringNode("", fmt.Sprintf("%d TB", size))
					}
				}
			}
		}

		return result, nil
	})

	ajson.AddFunction("base64_decode", func(node *ajson.Node) (result *ajson.Node, err error) {
		if node.IsString() {
			decoded, err := base64.StdEncoding.DecodeString(node.MustString())
			if err != nil {
				return nil, err
			}
			return ajson.StringNode("", string(decoded)), nil
		}
		return node, fmt.Errorf("base64_decode: unknown data type %d", node.Type())

	})

	ajson.AddFunction("base64_to_hex", func(node *ajson.Node) (result *ajson.Node, err error) {
		if node.IsString() {
			decoded, err := base64.StdEncoding.DecodeString(node.MustString())
			if err != nil {
				return nil, err
			}

			var str string
			if len(decoded) > 0 {
				str = fmt.Sprintf("0x%s", hex.EncodeToString(decoded))
			}
			return ajson.StringNode("", str), nil
		}
		return node, fmt.Errorf("base64_decode: unknown data type %d", node.Type())

	})

	ajson.AddFunction("localtime", func(node *ajson.Node) (result *ajson.Node, err error) {
		if node.IsNumeric() {
			unixTime := int64(node.MustNumeric())
			ts := time.Unix(unixTime, 0)
			return ajson.StringNode("", ts.Format("2006-01-02 15:04:05 MST")), nil
		}
		return node, fmt.Errorf("localtime: unknown data type %d", node.Type())

	})
}

type Output struct {
	OutputMessage string
	JSONObject    interface{}
	OutputType    string
	TableColumns  []Column
	Filter        string

	root *ajson.Node
}

type Column struct {
	Name     string
	JSONPath string
	Expr     string
}

func (f *Output) Print() error {
	buf, err := json.Marshal(f.JSONObject)
	if err != nil {
		return err
	}

	f.root, err = ajson.Unmarshal(buf)
	if err != nil {
		return err
	}

	if !f.root.IsObject() && !f.root.IsArray() && !f.root.IsNull() {
		return fmt.Errorf("output %d must be an object or array", f.root.Type())
	}

	err = f.filterRows()
	if err != nil {
		return err
	}

	// No output type set, default to table
	if f.OutputType == "" {
		f.OutputType = "table"
	}

	if f.OutputType == "table" {
		return f.outputTable()
	} else if f.OutputType == "json" {
		return f.outputJSON()
	} else if f.OutputType == "yaml" {
		return f.outputYAML()
	}

	return fmt.Errorf("unsupported output type: %s", f.OutputType)
}

func (f *Output) Println() error {
	err := f.Print()
	if err != nil {
		return err
	}

	if f.OutputType == "table" {
		fmt.Fprintln(outputOrStdout())
	}
	return nil
}

func (f *Output) filterRows() error {

	if f.root.IsArray() {
		var filteredDocument []*ajson.Node

		for _, ajsonRow := range f.root.MustArray() {
			meetsFilter, err := f.checkMeetsFilter(ajsonRow)
			if err != nil {
				return err
			}
			if !meetsFilter {
				continue
			}

			filteredDocument = append(filteredDocument, ajsonRow)
		}

		f.root = ajson.ArrayNode("", filteredDocument)

		return nil
	} else if f.root.IsObject() {
		meetsFilter, err := f.checkMeetsFilter(f.root)
		if err != nil {
			return err
		}
		if !meetsFilter {
			f.root = ajson.ObjectNode("", nil)
		}

		return nil
	} else if f.root.IsNull() {
		return nil
	}

	return fmt.Errorf("cannot filter rows of an ajson object of type %d", f.root.Type())
}

func (f *Output) outputYAML() error {
	var output *ajson.Node
	if f.OutputMessage == "" {
		output = f.root
	} else {
		output = ajson.ObjectNode("", map[string]*ajson.Node{
			"msg":     ajson.StringNode("", f.OutputMessage),
			"content": f.root,
		})
	}

	document, err := ajson.Marshal(output)
	if err != nil {
		return err
	}

	yamlDocument, err := yaml.JSONToYAML(document)
	if err != nil {
		return err
	}

	fmt.Fprintln(outputOrStdout(), "---")
	fmt.Fprintln(outputOrStdout(), string(yamlDocument))
	return nil
}

func (f *Output) outputJSON() error {
	var output *ajson.Node
	if f.OutputMessage == "" {
		output = f.root
	} else {
		output = ajson.ObjectNode("", map[string]*ajson.Node{
			"msg":     ajson.StringNode("", f.OutputMessage),
			"content": f.root,
		})
	}

	document, err := AJSONToIndentedJSON(output, " ", " ")
	if err != nil {
		return err
	}

	fmt.Fprintln(outputOrStdout(), string(document))
	return nil
}

func (f *Output) outputTable() error {
	table := simpletable.New()

	if len(f.TableColumns) < 1 {
		return fmt.Errorf("no output columns have been set")
	}

	table.Header = &simpletable.Header{}
	for _, col := range f.TableColumns {
		table.Header.Cells = append(table.Header.Cells, &simpletable.Cell{
			Align: simpletable.AlignCenter,
			Text:  col.Name,
		})
	}

	table.Body = &simpletable.Body{}
	if !f.root.IsNull() {
		// Objects get printed as a single row table
		if f.root.IsObject() {
			f.root = ajson.ArrayNode("", []*ajson.Node{f.root})
		}

		for i, ajsonRow := range f.root.MustArray() {
			row, err := f.formatPathRow(ajsonRow)
			if err != nil {
				return fmt.Errorf("unable to format path row[%d] %s: %w", i+1, ajsonRow.String(), err)
			}
			table.Body.Cells = append(table.Body.Cells, row)
		}
	}

	table.SetStyle(simpletable.StyleCompactClassic)
	if f.OutputMessage != "" {
		fmt.Fprintf(outputOrStdout(), "[ %s ]\n", f.OutputMessage)
	}
	fmt.Fprintln(outputOrStdout(), table.String())

	return nil
}

func (f *Output) checkMeetsFilter(root *ajson.Node) (bool, error) {
	if f.Filter != "" {
		node, err := ajson.Eval(root, f.Filter)
		if err != nil {
			return false, fmt.Errorf("filter `%s`: %w", f.Filter, err)
		}
		if !node.IsBool() {
			return false, nil
		}
		return node.GetBool()
	}

	return true, nil
}

func (f *Output) formatPathRow(root *ajson.Node) ([]*simpletable.Cell, error) {
	formatPathRowError := func(err error) ([]*simpletable.Cell, error) {
		return []*simpletable.Cell{}, err
	}
	var err error

	var row []*simpletable.Cell
	for i, col := range f.TableColumns {
		var cell *simpletable.Cell

		if col.Expr != "" {
			cell, err = f.formatEvalExpr(root, col.Expr)
			if err != nil {
				return formatPathRowError(err)
			}
		} else if col.JSONPath != "" {
			cell, err = f.formatJSONPATH(root, col.JSONPath)
			if err != nil {
				return formatPathRowError(err)
			}
		} else {
			return formatPathRowError(fmt.Errorf("no expression or jsonpath set for column %s[%d]", col.Name, i+1))
		}

		row = append(row, cell)
	}

	return row, nil
}

func (f *Output) formatEvalExpr(root *ajson.Node, expr string) (*simpletable.Cell, error) {
	node, err := ajson.Eval(root, expr)
	if err != nil {
		return nil, err
	}

	value, err := node.Value()
	if err != nil {
		return nil, err
	}
	var column bytes.Buffer
	_, err = fmt.Fprint(&column, value)
	if err != nil {
		return nil, err
	}

	return &simpletable.Cell{Text: column.String()}, nil
}

func (f *Output) formatJSONPATH(root *ajson.Node, jsonPath string) (*simpletable.Cell, error) {
	buf, err := ajson.Marshal(root)
	if err != nil {
		return nil, err
	}
	col, err := ajson.JSONPath(buf, jsonPath)
	if err != nil {
		return nil, err
	}

	var column bytes.Buffer
	if len(col) == 1 {
		value, err := col[0].Value()
		if err != nil {
			return nil, err
		}
		_, err = fmt.Fprint(&column, value)
		if err != nil {
			return nil, err
		}
	} else {
		_, err = fmt.Fprint(&column, col)
		if err != nil {
			return nil, err
		}
	}

	return &simpletable.Cell{Text: column.String()}, nil
}

func AJSONToIndentedJSON(root *ajson.Node, prefix, indent string) ([]byte, error) {
	jsonBytes, err := ajson.Marshal(root)
	if err != nil {
		return nil, err
	}

	var jsonObj interface{}
	err = json.Unmarshal(jsonBytes, &jsonObj)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(jsonObj, prefix, indent)
}

func outputOrStdout() io.Writer {
	if outputWriter != nil {
		return outputWriter
	}
	return os.Stdout
}

func SetOut(out io.Writer) {
	outputWriter = out
}
