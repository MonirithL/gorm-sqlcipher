package sqlite3

/*
#cgo CFLAGS: -I./libtomcrypt/src/headers
#cgo CFLAGS: -DSQLITE_HAS_CODEC
#cgo CFLAGS: -DSQLITE_EXTRA_INIT=sqlcipher_extra_init
#cgo CFLAGS: -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
#cgo CFLAGS: -DSQLCIPHER_CRYPTO_LIBTOMCRYPT
#cgo CFLAGS: -DSQLITE_TEMP_STORE=2

#cgo LDFLAGS: -L./libtomcrypt -ltomcrypt -lm
*/
import "C"
