## signin

This is custom vector management application.

We can insert some integer values into vector structure, the vector structure consists with two members, first is vector begin, second is vector end pointer

The vulnerability is based on this application does not have logic for checking deleted index

```C
unsigned __int64 sub_1034()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>(&std::cout, "Index:");
  std::istream::operator>>(&std::cin, &v1);
  if ( v1 == 1 )
    sub_1364((__int64)&unk_2032A0);
  if ( v1 == 2 )
    sub_1364((__int64)&unk_2032C0);
  return __readfsqword(0x28u) ^ v2;
}

```

We can trigger delete function for same values more than one times.

Thus, we can make the vector end pointer smaller than the vector begin pointer.

We can make main_arena address into heap, just execute ‘new’ function many times.

And then, just use the show function to leak some values and calculate the libc base address.

Finally, we can get privileges on the server by overwriting tcache single-linked list pointer to __free_hook global variable.