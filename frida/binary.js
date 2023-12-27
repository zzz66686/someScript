//var str_name_so = "liblinkkit.so"; 
//var n_addr_func_offset = 0x7FAB1F2F88 - 0x7FAB19D000;    
//var n_addr_so = Module.findBaseAddress(str_name_so); 
//var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
//var ptr_func = new NativePointer(n_addr_func);




function zmqHook() {
    var zmq_msg_dataAddr = Module.findExportByName("libzmq.so", "zmq_msg_data");
    console.log("zmq_msg_data", zmq_msg_dataAddr)

    var zmq_msg_dataFunc = new NativeFunction(zmq_msg_dataAddr, "pointer", ["pointer"])



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

    var zmq_msg_recvfunc = Module.findExportByName("libzmq.so", "zmq_msg_recv");
    console.log(zmq_msg_recvfunc)
    Interceptor.attach(zmq_msg_recvfunc, {
        onEnter: function (args) {
            send("Enter zmq_msg_recv");
            //send("args[0] =" + args[0]); 

            var dataAddress = zmq_msg_dataFunc(args[0])
            //send("dataAddress =" + dataAddress); 
            this.dataAddress = dataAddress

            //console.log(Memory.readByteArray(dataAddress, 0x40))

            //send(Memory.readByteArray(dataAddress, 0x40))
            //send("args[1]=" + args[1].readCString());
        },
        onLeave: function (retval) {
            send("Leave zmq_msg_recv");
            send("size:" + retval);
            var retProtodata = Memory.readByteArray(this.dataAddress, retval.toInt32())
            console.log(retProtodata)
            send("protoData", retProtodata);
            // if (retval == 0x35){
            //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            //    send(backtrace);
            // };

        }
    });


    var zmq_recvfunc = Module.findExportByName("libzmq.so", "zmq_recv");
    console.log(zmq_recvfunc)
    Interceptor.attach(zmq_recvfunc, {
        onEnter: function (args) {
            send("Enter zmq_recv");
            //send("args[0] =" + args[0]); 
            //var dataAddress = zmq_msg_data(args[0])
            //send("dataAddress =" + dataAddress); 
            //console.log(Memory.readByteArray(dataAddress, 0x40))
            //send(Memory.readByteArray(dataAddress, 0x40))
            //send("args[1]=" + args[1].readCString());
        },
        onLeave: function (retval) {
            //send("Leave zmq_recv");
            send("size:" + retval);
            // if (retval == 0x35){
            //    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            //    send(backtrace);
            // };

        }
    });



}




function fileInit() {
    Java.perform(function () {
        Java.use("java.io.File").$init.overload('java.io.File', 'java.lang.String').implementation = function (file, name) {
            var result = this.$init(file, name)
            //var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            //console.log(file.getPath())
            //if (/*file.getPath().indexOf("cacert") >= 0 && */stack.indexOf("X509TrustManagerExtensions.checkServerTrusted") >= 0) {
            console.log(file.getPath() + "/" + name)
            // console.log(name)
            //console.log(stack)
            //}
            return result;
        }
    })


    Java.perform(function () {
        Java.use("java.io.File").$init.overload('java.lang.String').implementation = function (s) {
            var result = this.$init(s)
            console.log(s)
            return result;
        }
    })

    Java.perform(function () {
        Java.use("java.io.File").$init.overload('java.lang.String', 'java.lang.String').implementation = function (s0, s1) {
            var result = this.$init(s0, s1)
            console.log(s0 + s1)
            return result;
        }
    })
}




function openFile() {
    var openAddr = Module.findExportByName(null, "open64");
    var openPtr = new NativePointer(openAddr)

    Interceptor.attach(openPtr, {
        onEnter: function (args) {
            console.log("Enter open64");
            console.log(args[0].readCString())
        },
        onLeave: function (retval) {
            console.log("Leave open64");
        }
    });
}

zmqHook()
