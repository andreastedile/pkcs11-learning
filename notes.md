# Notes

## PyKCS11

| function                      | type                              |
|-------------------------------|-----------------------------------|
| generateKeyPair               | PyKCS11.LowLevel.CK_OBJECT_HANDLE |
| generateKey                   | PyKCS11.LowLevel.CK_OBJECT_HANDLE |
| encrypt                       | PyKCS11.ckbytelist                |
| decrypt                       | PyKCS11.ckbytelist                |
| wrap                          | PyKCS11.ckbytelist                |
| unwrap                        | PyKCS11.LowLevel.CK_OBJECT_HANDLE |
| getAttributeValue + CKA_VALUE | tuple[int]                        |
