package models

import "golang.org/x/crypto/bcrypt"

//Config data
type Config struct {
	Hash func(string) (string, error)
	//Should define some policy
	CompareHash   func(string, string) error
	AccessSecret  string
	RefreshSecret string
}

func hashPassword(pwd string) (string, error) {
	bytePwd := []byte(pwd)
	hash, err := bcrypt.GenerateFromPassword(bytePwd, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), err
}

func compareHashPassword(pwd string, hash string) error {
	byteHashPwd := []byte(hash)
	return bcrypt.CompareHashAndPassword(byteHashPwd, []byte(pwd))
}

//DefaultConfig for quick implement
var DefaultConfig = &Config{hashPassword, compareHashPassword, "hkhfkalknknvlzaoiis", "hqihoahfonogaosngoa"}
