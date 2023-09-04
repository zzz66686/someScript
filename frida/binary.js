//var str_name_so = "liblinkkit.so"; 
//var n_addr_func_offset = 0x7FAB1F2F88 - 0x7FAB19D000;    
//var n_addr_so = Module.findBaseAddress(str_name_so); 
//var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
////var ptr_func = new NativePointer(n_addr_func);



var zmq_msg_datafunc = Module.findExportByName("libzmq.so","zmq_msg_data");
console.log("zmq_msg_data", zmq_msg_datafunc)

var zmq_msg_sizefunc = Module.findExportByName("libzmq.so","zmq_msg_size");
console.log("zmq_msg_size", zmq_msg_sizefunc)

var zmq_msg_data = new NativeFunction(zmq_msg_datafunc, "pointer", ["pointer"])
var zmq_msg_size = new NativeFunction(zmq_msg_sizefunc, "int", ["pointer"])

// Interceptor.attach(zmq_msg_datafunc, {
//     onEnter: function(args) {
//         send("Enter zmq_msg_data");
//         send("args[0]=" + args[0]); 
//         //send("args[1]=" + args[1].readCString());
//     },
//     onLeave: function(retval){
//         send("Leave zmq_msg_data");
//         send("return:"+retval);
//         //if (retval >= 0x76 && retval <= 0x79){
//         //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
//         //    send(backtrace);
//         //};

//     }
// });


// var zmq_msg_sendfunc = Module.findExportByName("libzmq.so","zmq_msg_send");
// console.log(zmq_msg_sendfunc)

// Interceptor.attach(zmq_msg_sendfunc, {
//     onEnter: function(args) {
//         send("Enter zmq_msg_send");
//         //send("args[0] =" + args[0]); 
//         var dataAddress = zmq_msg_data(args[0])
//         //send("dataAddress =" + dataAddress); 
//         console.log(Memory.readByteArray(dataAddress, 0x40))
//         //send(Memory.readByteArray(dataAddress, 0x40))
//         //send("args[1]=" + args[1].readCString());
//     },
//     onLeave: function(retval){
//         //send("Leave zmq_msg_send");
//         send("size:"+retval);
//         // if (retval == 0x35){
//         //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
//         //    send(backtrace);
//         // };

//     }
// });

var zmq_msg_recvfunc = Module.findExportByName("libzmq.so","zmq_msg_recv");
console.log(zmq_msg_recvfunc)
Interceptor.attach(zmq_msg_recvfunc, {
    onEnter: function(args) {
        send("Enter zmq_msg_recv");
        //send("args[0] =" + args[0]); 

        var dataAddress = zmq_msg_data(args[0])
        //send("dataAddress =" + dataAddress); 
        this.dataAddress = dataAddress

        //console.log(Memory.readByteArray(dataAddress, 0x40))
        
        //send(Memory.readByteArray(dataAddress, 0x40))
        //send("args[1]=" + args[1].readCString());
    },
    onLeave: function(retval){
        send("Leave zmq_msg_recv");
        send("size:"+retval);
        var retProtodata =Memory.readByteArray(this.dataAddress, retval.toInt32())
        console.log(retProtodata)
        send("protoData", retProtodata);
        // if (retval == 0x35){
        //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
        //    send(backtrace);
        // };

    }
});


var zmq_recvfunc = Module.findExportByName("libzmq.so","zmq_recv");
console.log(zmq_recvfunc)
Interceptor.attach(zmq_recvfunc, {
    onEnter: function(args) {
        send("Enter zmq_recv");
        //send("args[0] =" + args[0]); 
        //var dataAddress = zmq_msg_data(args[0])
        //send("dataAddress =" + dataAddress); 
        //console.log(Memory.readByteArray(dataAddress, 0x40))
        //send(Memory.readByteArray(dataAddress, 0x40))
        //send("args[1]=" + args[1].readCString());
    },
    onLeave: function(retval){
        //send("Leave zmq_recv");
        send("size:"+retval);
        // if (retval == 0x35){
        //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
        //    send(backtrace);
        // };

    }
});

