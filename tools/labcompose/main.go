// labcompose connects the lab wrapper/watcher to a closed read pipe.
package main

import (
 "bufio"
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "time"
 wrapper "github.com/relux-works/swarma-keyvault/lab/namecoinwrapper"
 watch "github.com/relux-works/swarma-keyvault/lab/sealwatch"
)
type pipe struct{ scanner *bufio.Scanner; calls int }
func (p *pipe) raw(ctx context.Context, method string, args ...any)(json.RawMessage,error){
 switch method {case "getblockchaininfo","getblockhash","getblockheader","name_show","getrawtransaction","gettxout","getrawmempool","getblock": default:return nil,fmt.Errorf("read method denied")}
 if ctx.Err()!=nil || p.calls>=256{return nil,fmt.Errorf("read bound")};p.calls++
 if err:=json.NewEncoder(os.Stdout).Encode(map[string]any{"rpc":method,"params":args});err!=nil{return nil,err}
 if !p.scanner.Scan(){return nil,fmt.Errorf("read pipe closed")}
 var response struct{Result json.RawMessage `json:"result"`; Failed bool `json:"failed"`}
 if json.Unmarshal(p.scanner.Bytes(),&response)!=nil || response.Failed{return nil,fmt.Errorf("read pipe failed")}
 return response.Result,nil
}
type wpipe struct{p *pipe}
func(w wpipe)Call(ctx context.Context,m string,a ...any)(json.RawMessage,error){return w.p.raw(ctx,m,a...)}
type spipe struct{p *pipe}
func(s spipe)Call(ctx context.Context,m string,a ...any)(io.ReadCloser,error){b,e:=s.p.raw(ctx,m,a...);return io.NopCloser(bytes.NewReader(b)),e}
type input struct {Policy wrapper.Policy; Binding watch.Binding; Certificate,Request string; At time.Time; Mode string}
func main(){
 if len(os.Args)!=2{os.Exit(2)}
 b,e:=os.ReadFile(os.Args[1]);if e!=nil{os.Exit(2)}
 var in input;if json.Unmarshal(b,&in)!=nil{os.Exit(2)}
 sc:=bufio.NewScanner(os.Stdin);sc.Buffer(make([]byte,4096),8<<20)
 p:=&pipe{scanner:sc}
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 if in.Mode=="watch" {
  l:=watch.DefaultLimits();l.Polls=1
  v:=watch.New(spipe{p}).Watch(ctx,in.Binding,l)
  json.NewEncoder(os.Stdout).Encode(map[string]any{"done":true,"watch":v});return
 }
 cert,e:=os.ReadFile(in.Certificate);if e!=nil{os.Exit(2)};req,e:=os.ReadFile(in.Request);if e!=nil{os.Exit(2)}
 cli,e:=os.ReadFile(in.Policy.CLI);if e!=nil{os.Exit(2)};h:=sha256.Sum256(cli);in.Policy.CLIHash=hex.EncodeToString(h[:])
 observation,err:=new(wrapper.Verifier).Verify(ctx,wpipe{p},in.Policy,cert,req,in.At)
 result:=map[string]any{"done":true,"verified":err==nil,"observation":observation,"read_calls":p.calls}
 if err!=nil{result["error"]="lab verification refused"}
 json.NewEncoder(os.Stdout).Encode(result)
}
