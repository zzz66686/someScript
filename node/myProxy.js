

let mydocument = {
    "head": {},
    "documentElement": {    },
    "readyState": "complete",
    "addEventListener": function () { },
    "createElement": function () { return {} },
    "getElementsByTagName": function (str) {
        console.log(str)
    }
}
let mynavigator = {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    platform: "Win32",
    appCodeName: "Mozilla",
    languages: ['zh-CN', 'zh', 'en'],
    cookieEnabled: true,
    webdriver: false,
};
let mysrceen = {
    height: 1080,
    width: 1920,
    colorDepth: 24,
};
let mylocation = {
    "protocol": "https:",
    "href": "https://baike.baidu.com/",
    "pathname": "/",
    "host": "baike.baidu.com",
    "hostname": "baike.baidu.com",
};
let myhistory =  {
    "length" : 2
};

let mywindow = {
    XMLHttpRequest: function () {    },
    sessionStorage: {},
    localStorage: {},
    
    scrollTo: function () {    },
    addEventListener: function () {    },
    attachEvent: function () {    },
    chrome: {},
    screen: mysrceen,
    location: mylocation,
    document: mydocument,
    navigator: mynavigator,
    history:myhistory,
};







let rawindexof = String.prototype.indexOf
String.prototype.indexOf = function (str) {
    var res = rawindexof.call(this, str)
    console.log(`[String] "${this}" is indexof "${str}", res is ${res}`)
    return res
}


// let rawstringify = JSON.stringify;
// JSON.stringify = function (Object) {
//     if ((Object?.value ?? Object) === global) {
//         return "global"
//     } else {
//         return rawstringify(Object)
//     }
// }




function getObjhandler(WatchName) {
    let handler = {
        get(target, propKey, receiver) {
            let result = Reflect.get(target, propKey, receiver)
            if (result instanceof Object) {
                if (typeof result === "function") {
                    console.log(`[${WatchName}] getting propKey is [${propKey}] , it is function`)
                } else {
                    console.log(`[${WatchName}] getting propKey is [${propKey}], result is [${JSON.stringify(result)}]`);
                }
                return new Proxy(result, getObjhandler(`${WatchName}.${propKey}`))
            }
            console.log(`[${WatchName}] getting propKey is [${propKey}], result is [${result}]`);
            return result;
        },
        set(target, propKey, value, receiver) {
            if (value instanceof Object) {
                console.log(`[${WatchName}] setting propKey is [${propKey}], value is [${JSON.stringify(value)}]`);
            } else {
                console.log(`[${WatchName}] setting propKey is [${propKey}], value is [${value}]`);
            }
            return Reflect.set(target, propKey, value, receiver);
        },
        has(target, propKey) {
            var result = Reflect.has(target, propKey);
            console.log(`[${WatchName}] has propKey [${propKey}], result is [${result}]`)
            return result;
        },
        deleteProperty(target, propKey) {
            var result = Reflect.deleteProperty(target, propKey);
            console.log(`[${WatchName}] delete propKey [${propKey}], result is [${result}]`)
            return result;
        },
        getOwnPropertyDescriptor(target, propKey) {
            var result = Reflect.getOwnPropertyDescriptor(target, propKey);
            console.log(`[${WatchName}] getOwnPropertyDescriptor  propKey [${propKey}] result is [${JSON.stringify(result)}]`)
            return result;
        },
        defineProperty(target, propKey, attributes) {
            var result = Reflect.defineProperty(target, propKey, attributes);
            console.log(`[${WatchName}] defineProperty propKey [${propKey}] attributes is [${JSON.stringify(attributes)}], result is [${result}]`)
            return result
        },
        getPrototypeOf(target) {
            var result = Reflect.getPrototypeOf(target)
            console.log(`[${WatchName}] getPrototypeOf result is [${JSON.stringify(result)}]`)
            return result;
        },
        setPrototypeOf(target, proto) {
            console.log(`[${WatchName}] setPrototypeOf proto is [${JSON.stringify(proto)}]`)
            return Reflect.setPrototypeOf(target, proto);
        },
        preventExtensions(target) {
            console.log(`[${WatchName}] preventExtensions`)
            return Reflect.preventExtensions(target);
        },
        isExtensible(target) {
            var result = Reflect.isExtensible(target)
            console.log(`[${WatchName}] isExtensible, result is [${result}]`)
            return result;
        },
        ownKeys(target) {
            var result = Reflect.ownKeys(target)
            console.log(`[${WatchName}] invoke ownkeys, result is [${JSON.stringify(result)}]`)
            return result
        },
        apply(target, thisArg, argArray) {
            let result = Reflect.apply(target, thisArg, argArray)
            console.log(`[${WatchName}] apply function name is [${target.name}], argArray is [${argArray}], result is [${result}].`)
            return result
        },
        construct(target, argArray, newTarget) {
            var result = Reflect.construct(target, argArray, newTarget)
            console.log(`[${WatchName}] construct function name is [${target.name}], argArray is [${argArray}], result is [${JSON.stringify(result)}].`)
            return result;
        }
    }
    return handler;
}

const navigator = new Proxy(Object.create(mynavigator), getObjhandler("navigator"));
const screen = new Proxy(Object.create(mysrceen), getObjhandler("screen"));
const location = new Proxy(mylocation, getObjhandler("location"));
const document = new Proxy(mydocument, getObjhandler("document"));
const window = new Proxy(Object.assign(global, mywindow), getObjhandler("window"));
const history = new Proxy(Object.create(myhistory), getObjhandler("history"));


module.exports = {
    window,
    navigator,
    screen,
    location,
    String,
    history,
    document
}
