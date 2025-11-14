# gorm-sqlcipher
This version of gorm-sqlcipher was created specifically to work with my enpass CLI, which requires `_pragma_cipher_compatibility=3`. This was achieved by using an older version of [go-sqliciper](github.com/mutecomm/go-sqlcipher) that still supports compatibility 3. I also had to fix a couple of bugs in `sqlite.go` that were present in every other library I tried.

## Installation

go get github.com/gdanko/gorm-sqlcipher

## How to use

```go
import (
	sqlcipher "github.com/gdanko/gorm-sqlcipher"
	"gorm.io/gorm"
)

key := "2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99"
dbFile := "/path/to/my.db"
dbName := fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_compatibility=3", dbFile, key)
db, err := gorm.Open(sqlcipher.Open(dbName), &gorm.Config{})
```

## More


- Zetetic LLC : https://github.com/sqlcipher/sqlcipher
- LibTomCrypt : https://github.com/libtom/libtomcrypt
- Yasuhiro Matsumoto (a.k.a mattn): https://github.com/mattn/go-sqlite3
- Gdanko : https://github.com/gdanko/gorm-sqlcipher
- Gorm : https://github.com/go-gorm/gorm
- Mutecomm: https://github.com/mutecomm/go-sqlcipher


__other relevant liscensing is here: https://github.com/MonirithL/go-sqlcipher__
