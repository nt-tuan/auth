package auth

import "errors"

//ErrEmailExist error
var ErrEmailExist = errors.New("email existed")

//ErrUsernameExist error
var ErrUsernameExist = errors.New("username existed")

//ErrTokenExpire error
var ErrTokenExpire = errors.New("token expired")

//ErrInvalidToken error
var ErrInvalidToken = errors.New("invalid token")

//ErrPasswordInvalid error
var ErrPasswordInvalid = errors.New("username and password mismatch")
