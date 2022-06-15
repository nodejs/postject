// This is modeled after
// https://source.chromium.org/chromium/chromium/src/+/main:third_party/crashpad/crashpad/client/crashpad_info_note.S;drc=8371af273f35eb989520360435fb81a730d6a593

  .section .note.crashpad.resource,"a",%note
  .balign 4
POSTJECT_NOTE:
  .long name_end - name  // namesz
  .long desc_end - desc  // descsz
  .long 0x5f464f49       // type
name:
  .asciz "postject"
name_end:
  .balign 4
desc:
  .long rname_end - rname  // rnamesz
rname:
  .asciz "barbar"  // rname - Customize this to what you want
rname_end:
  .incbin "foo.txt"  // resoource content
desc_end:
  .size POSTJECT_NOTE, .-POSTJECT_NOTE
