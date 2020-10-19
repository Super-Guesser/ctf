## fixed camera

The given Unity binary uses il2cpp + mono. It is easily reversible with Il2CppDumper.

With the dumper, it was able to find out that there's a class named `cam` and it has the main logic.

The structure of the member of the class was like:

```
00000000 cam_Fields      struc ; (sizeof=0x48, align=0x8, copyof_17367)
00000000                                         ; XREF: cam_o/r
00000000 baseclass_0     UnityEngine_MonoBehaviour_Fields ?
00000008 text            dq ?                    ; offset
00000010 encrypt_flag    dq ?                    ; offset
00000018 speed           dd ?
0000001C distance_v      dd ?
00000020 distance_h      dd ?
00000024 rotation_H_speed dd ?
00000028 rotation_V_speed dd ?
0000002C max_up_angle    dd ?
00000030 max_down_angle  dd ?
00000034 max_left_angle  dd ?
00000038 max_right_angle dd ?
0000003C current_rotation_V dd ?
00000040 angleY          dq ?                    ; offset
00000048 cam_Fields      ends
```

The important field is `angleY`, because we cannot move over `-9` degree or `+9` degree because of the code. At this time, I decided to use cheat engine to change `angleY` value.

It was able to find `angleY` from the memory because of other member values.

```c
void __stdcall cam___ctor(cam_o *this, const MethodInfo *method)
{
  __int64 v3; // rdx
  UnityEngine_MonoBehaviour_o *v4; // rbx

  if ( !byte_180872E55 )
  {
    sub_18011A030(10994i64, (__int64)method);
    byte_180872E55 = 1;
  }
  v3 = StringLiteral_3877;
  this->fields.encrypt_flag = (struct System_String_o *)StringLiteral_3877;
  sub_180119BC0((__int64)&this->fields.encrypt_flag, v3);
  this->fields.speed = 20.0;
  this->fields.rotation_H_speed = 1.0;
  this->fields.rotation_V_speed = 1.0;
  this->fields.max_up_angle = 80.0;
  this->fields.max_down_angle = -60.0;
  this->fields.max_left_angle = -30.0;
  this->fields.max_right_angle = 30.0;
  v4 = (UnityEngine_MonoBehaviour_o *)sub_18011A130(EncryptValue_TypeInfo);
  UnityEngine_MonoBehaviour___ctor(v4, 0i64);
  this->fields.angleY = (struct EncryptValue_o *)v4;
  sub_180119BC0((__int64)&this->fields.angleY, (__int64)v4);
  UnityEngine_MonoBehaviour___ctor((UnityEngine_MonoBehaviour_o *)this, 0i64);
}
```

Member values like `speed`, `max_up_angle`, `max_down_angle` are never changed after the given constructor fix its value. Therefore, it was able to find the pointer `angleY` by finding values `[20.0, 1.0, 1.0, 80.0, -60.0, -30.0, 30.0]`.

After this, I changed `angleY` to `-120` and moved slowly to right. When `angleY` was `-60`, the flag was out, it was `n1ctf{encrypt_value}`.