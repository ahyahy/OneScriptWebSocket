using System;
using System.Net;
using System.Net.WebSockets;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.HostedScript.Library;
using ScriptEngine.Machine;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace OSWebSocket
{
    [ContextClass("СвДействие", "SwAction")]
    public class SwAction : AutoContext<SwAction>
    {
        public SwAction(IRuntimeContextInstance script, string methodName, IValue param = null)
        {
            Script = script;
            MethodName = methodName;
            Parameter = param;
        }

        public SwAction()
        {
        }

        [ContextProperty("ИмяМетода", "MethodName")]
        public string MethodName { get; set; }

        [ContextProperty("Сценарий", "Script")]
        public IRuntimeContextInstance Script { get; set; }

        [ContextProperty("Параметр", "Parameter")]
        public IValue Parameter { get; set; }
    }
}
