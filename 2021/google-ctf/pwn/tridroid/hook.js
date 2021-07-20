var jni = ptr(0);
// Interceptor.attach(Module.findBaseAddress('libtridroid.so').add(0x1420), {
//     onEnter(args) {
//     },
//     onLeave(retval) {
//         // console.log(jni);
//         // if (retval.readPointer() == jni) {
//         //     console.log("found")
//         // }
//     },
// });
Interceptor.attach(Module.getExportByName('libtridroid.so', 'Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack__Ljava_lang_String_2_3B'), {
    onEnter(args) {
        console.log("jnienv", args[0]);
        console.log("jobj", args[1]);
        // jni = args[0];
    },
    onLeave(retval) {

    },
});
