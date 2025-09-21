using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ScriptEngine.Machine;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.HostedScript.Library;

namespace OSWebSocket
{
    public class WebSocetClient
    {
        public SwWebSocetClient dll_obj;
        public WebSocketSharp.WebSocket M_WebSocetClient;

        public WebSocetClient(string p1, string[] p2 = null)
        {
            M_WebSocetClient = new WebSocketSharp.WebSocket(p1, p2);
            M_WebSocetClient.OnClose += M_WebSocetClient_OnClose;
            M_WebSocetClient.OnError += M_WebSocetClient_OnError;
            M_WebSocetClient.OnMessage += M_WebSocetClient_OnMessage;
            M_WebSocetClient.OnOpen += M_WebSocetClient_OnOpen;
        }

        private void M_WebSocetClient_OnOpen(object sender, System.EventArgs e)
        {
            if (dll_obj.Connected != null)
            {
                SwEventArgs SwEventArgs1 = new SwEventArgs();
                SwEventArgs1.sender = dll_obj;
                SwEventArgs1.eventAction = dll_obj.Connected;
                OneScriptWebSocket.EventQueue.Enqueue(SwEventArgs1);
            }
        }

        private void M_WebSocetClient_OnMessage(object sender, WebSocketSharp.MessageEventArgs e)
        {
            if (dll_obj.AtMessageReceived != null)
            {
                SwMessageEventArgs SwMessageEventArgs1 = new SwMessageEventArgs();
                SwMessageEventArgs1.sender = dll_obj;
                SwMessageEventArgs1.eventAction = dll_obj.AtMessageReceived;
                SwMessageEventArgs1.message = e.Data;
                OneScriptWebSocket.EventQueue.Enqueue(SwMessageEventArgs1);
            }
        }

        private void M_WebSocetClient_OnError(object sender, WebSocketSharp.ErrorEventArgs e)
        {
            if (dll_obj.AtError != null)
            {
                SwErrorEventArgs SwErrorEventArgs1 = new SwErrorEventArgs();
                SwErrorEventArgs1.sender = dll_obj;
                SwErrorEventArgs1.eventAction = dll_obj.AtError;
                SwErrorEventArgs1.errorException = e.Exception.ToString();
                SwErrorEventArgs1.errorMessage = e.Message;
                OneScriptWebSocket.EventQueue.Enqueue(SwErrorEventArgs1);
            }
        }

        private void M_WebSocetClient_OnClose(object sender, WebSocketSharp.CloseEventArgs e)
        {
            if (dll_obj.Disconnected != null)
            {
                SwCloseEventArgs SwCloseEventArgs1 = new SwCloseEventArgs();
                SwCloseEventArgs1.sender = dll_obj;
                SwCloseEventArgs1.eventAction = dll_obj.Disconnected;
                SwCloseEventArgs1.code = Convert.ToInt32(e.Code);
                SwCloseEventArgs1.reason = e.Reason;
                SwCloseEventArgs1.wasClean = e.WasClean;
                OneScriptWebSocket.EventQueue.Enqueue(SwCloseEventArgs1);
            }
        }

        public void Connect()
        {
            M_WebSocetClient.Connect();
        }

        //public void ConnectAsync()
        //{
        //    M_WebSocetClient.ConnectAsync();
        //}

        //public void CloseAsync()
        //{
        //    M_WebSocetClient.CloseAsync();
        //}

        public void Close()
        {
            M_WebSocetClient.Close();
        }

        public void Send(string data)
        {
            M_WebSocetClient.Send(data);
        }

        public void SendAsync(string data)
        {
            M_WebSocetClient.SendAsync(data, null);
        }

    }

    [ContextClass("СвВебСокетКлиент", "SwWebSocetClient")]
    public class SwWebSocetClient : AutoContext<SwWebSocetClient>
    {
        public SwWebSocetClient(string p1, ArrayImpl p2 = null)
        {
            WebSocetClient WebSocetClient1;
            if (p2 != null)
            {
                string[] array = new string[p2.Count()];

                ArrayImpl ArrayImpl1 = (ArrayImpl)p2;
                for (int i = 0; i < ArrayImpl1.Count(); i++)
                {
                    array[i] = ArrayImpl1.Get(i).AsString();
                }
                WebSocetClient1 = new WebSocetClient(p1, array);
            }
            else
            {
                WebSocetClient1 = new WebSocetClient(p1);
            }
            WebSocetClient1.dll_obj = this;
            Base_obj = WebSocetClient1;
        }

        public SwWebSocetClient()
        {

        }

        public WebSocetClient Base_obj;

        [ContextProperty("ПриОтключении", "Disconnected")]
        public IValue Disconnected { get; set; }

        [ContextProperty("ПриПодключении", "Connected")]
        public IValue Connected { get; set; }

        [ContextProperty("ПриПолученииСообщения", "AtMessageReceived")]
        public IValue AtMessageReceived { get; set; }

        [ContextProperty("ПриОшибке", "AtError")]
        public IValue AtError { get; set; }

        [ContextMethod("Подключить", "Connect")]
        public void Connect()
        {
            Base_obj.Connect();
        }

        [ContextMethod("Отключить", "Close")]
        public void Close()
        {
            Base_obj.Close();
        }

        [ContextMethod("Отправить", "Send")]
        public void Send(string data)
        {
            Base_obj.Send(data);
        }

        [ContextMethod("ОтправитьАсинхронно", "SendAsync")]
        public void SendAsync(string data)
        {
            Base_obj.SendAsync(data);
        }

    }
}
