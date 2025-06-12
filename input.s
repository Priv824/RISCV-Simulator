.data
.dword 20, 30, 40, 50, 60
.text
lui x3, 16
sd x0, 0(x3)
ld x4, 8(x3)
ld x4, 0(x3)
ld x4, 16(x3)
ld x4, 24(x3)
