//var str_name_so = "liblinkkit.so"; 
//var n_addr_func_offset = 0x7FAB1F2F88 - 0x7FAB19D000;    
//var n_addr_so = Module.findBaseAddress(str_name_so); 
//var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
////var ptr_func = new NativePointer(n_addr_func);
var zmq_msg_sendfunc = Module.findExportByName("libzmq.so","zmq_msg_send");
console.log(zmq_msg_sendfunc)

Interceptor.attach(zmq_msg_sendfunc, {
    onEnter: function(args) {
        send("Enter zmq_msg_send");
        send("args[0]=" + args[0]); 
        //send("args[1]=" + args[1].readCString());
    },
    onLeave: function(retval){
        send("Leave zmq_msg_send");
        send("return:"+retval);
        //if (retval >= 0x76 && retval <= 0x79){
        //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
        //    send(backtrace);
        //};

    }
});


