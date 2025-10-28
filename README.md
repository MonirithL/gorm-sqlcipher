# Attribution

if attribution means giving credits and thanks to people, then I would like to give attribution to:

- Zetetic LLC : https://github.com/sqlcipher/sqlcipher
- LibTomCrypt : https://github.com/libtom/libtomcrypt
- Yasuhiro Matsumoto (a.k.a mattn): https://github.com/mattn/go-sqlite3
- Gdanko : https://github.com/gdanko/gorm-sqlcipher
- Gorm : https://github.com/go-gorm/gorm

I have used sqlcipher to build and link with libtomcrypt for encryption. I was supposed to use openssl...and I did. but I then realized generic build of openssl is like marginally better(after some bad benchmarking but i guess it all run of software...). So I stuck to Libtomcrypt as it is simpler and elegant.

Then I replaced the mattn/go-sqlite3 sqlite3-binding.c and .h with the built sqlcipher files.
(sorry if there is no go.mod, git and links in the code to you, I did a replaced all to change module, then i realized that was my skill issue, my bad XD)

After that, I moved it to the Gdanko/gorm-sqlcipher folder and import it over https://github.com/mutecomm/go-sqlcipher

Finally some tweak here and there, like upgrading the text version and stuff with

> go get -u all

(not sure if it runs for all but I feel like it did)

Lastly, this is a custom build, and I do not know what I am doing. it is a mix of me+google+gemini2.5pro(debugging go run -x .)+chatgpt.

## USE AT YOUR OWN RISK!!!!

i checked it working by ONLY, create db and inserting stuff. Then, tried open as txt and dbeaver!
Any unintended consequences is your own responsibilities (Know this beforehand or you can validate it if u can/want).

# More Attribution

I will try to get this right as it is my first time reading the liscense requirements. pls forgive.

- Copyright (c) 2025, ZETETIC LLC All rights reserved.

all the liscense can be found in the ALL LICENSE folder. All use of this must reciprocate the licences there (strictly first, not strict last).

## Now time for the code:

```go
package main

import (
	"fmt"
	"log"
	"os"

	sqlite "github.com/MonirithL/gorm-sqlcipher"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Product struct {
	gorm.Model
	Code  string
	Price uint
}

func main() {
	dbName := "truly_encrypted.db"
	key := "this_is_the_real_key"

	//Delete the old database file, Best for repetitive testing
	_ = os.Remove(dbName)
	log.Println("Removed old database file (if any).")

	//Open empty conn
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	log.Println("Initial connection successful.")

	//pragma setting the key, can move this inside the Open() if possible (untested)
	if err := db.Exec(fmt.Sprintf("PRAGMA key = '%s';", key)).Error; err != nil {
		log.Fatalf("Failed to set PRAGMA key: %v", err)
	}
	log.Println("PRAGMA key successfully set.")

	//running all the other check insert, select, sqlite ver, sqlcipher ver
	log.Println("Migrating schema...")
	if err := db.AutoMigrate(&Product{}); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	log.Println("Creating record...")
	if err := db.Create(&Product{Code: "TOP_SECRET", Price: 1337}).Error; err != nil {
		log.Fatalf("Create failed: %v", err)
	}

	log.Println("Successfully created encrypted database and record!")
	log.Println("Now, try opening 'truly_encrypted.db' in a text editor.")
	var sqliteVersion string
	if err := db.Raw("SELECT sqlite_version();").Scan(&sqliteVersion).Error; err != nil {
		log.Fatalf("Failed to query SQLite version: %v", err)
	}
	log.Printf(">>>> SQLite Version: %s", sqliteVersion)

	var sqlcipherVersion string
	if err := db.Raw("PRAGMA cipher_version;").Scan(&sqlcipherVersion).Error; err != nil {
		log.Fatalf("Failed to query SQLCipher version: %v", err)
	}
	log.Printf(">>>> SQLCipher Version: %s", sqlcipherVersion)
}
```

xx Cheers
