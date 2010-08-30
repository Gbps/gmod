// This is where your public key is defined. Here, the XML parser loads the SNK into memory and uses it to decrypt the rest of the file.

#define __RSA_PRIVATE "<RSAKeyValue><Modulus>q6gR6IXPCpeBcyygcTIyBEYh47iotbtxxUKs+bSyCUjHQFgM9/2TBQrOG4pFN5Qm6rGJThi1a4LoPx2DClHibR7xDubZAK3nplq/FKlTuncNPEc23y5LdQHP/iwSPjujFL3R275KlVUEqnRL/BVkQ/2YYTTRfyDkWtJ1u3mlEYU=</Modulus><Exponent>AQAB</Exponent><P>1BNjlmmhQHIi/+YVzimQJOBCvkq+HhwUbDcbTSh9N0k0WLtJ54pPKOU7YQxtY8lNXdz0sibTngtrS5Me45x6pw==</P><Q>zzWWIH9T/4+a/5D+25hJdQFYNHe/RW1G+9W2EPKTIEWNGYvV7KDmOcnk8LRgQ+56EN/uqHjPXWSSGsl2FnPT8w==</Q><DP>Bg7HuXQq9vxLo6Oe29S0GVmOjoD0DUggDTdFwF53tSySIja3VbXNrQ1fNNZ2CXOmkhfNpYkWYl1RI0eAil/d4Q==</DP><DQ>WSXQ5UJivTznjrSvMYMfd3uQm2I5pIETXR3hKwFyUxwZTLhg3WGMK6i1Guo/0Ho1gjUV1N3FOYUfZu7uI1LKCQ==</DQ><InverseQ>gcg4gdwngy+qsYHprAggjFqzRDGU2/CiHxQ5nBJ4Yq24CsJhtsLHm3FUBXYdFtpf6OxPvVISRT6CakLUAISRjw==</InverseQ><D>aIiTT0ydRs/4rxDQK97rgprK7Ih5hSI/KGdwOyiE+w5s+IwmaabsLzfjR/YuLKh2AppXCU4WvQAdOsJYGKLBBb9qHmzw+6TTS2q7L/SM+6j0duydayg0h66RoulSy4mHrynjtIfgz2ceHF7o7z8uuTOuCrgjgPL2KCY6Mq2jBAk=</D></RSAKeyValue>"
#define __RSA_PUBLIC "<RSAKeyValue><Modulus>q6gR6IXPCpeBcyygcTIyBEYh47iotbtxxUKs+bSyCUjHQFgM9/2TBQrOG4pFN5Qm6rGJThi1a4LoPx2DClHibR7xDubZAK3nplq/FKlTuncNPEc23y5LdQHP/iwSPjujFL3R275KlVUEqnRL/BVkQ/2YYTTRfyDkWtJ1u3mlEYU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
#define __AES_IV "y$ph+FuYExeZ8qAB"