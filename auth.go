package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
)

//IAuth interface
type IAuth interface {
	//Login user based on their usr and psw, return access token and refresh token
	Login(usr string, psw string) (*string, *string, error)
	//Logout user based on their token
	Logout(token string) error
	//VerifyToken access token. Return error if token is invalid or expired
	VerifyToken(token string) (*AccessDetails, error)
	//RefreshToken ask to refresh token. Reture access token and refresh token and error if token is expire or token is invalid
	RefreshToken(token string) (string, string, error)
	//Register account
	Register(*Account, string) error
}

//AccessDetails stored in jwt
type AccessDetails struct {
	AccessUUID string
	UserID     uint
	AtExpires  *time.Time
}

//RefreshDetails stored in jwt
type RefreshDetails struct {
	RefreshUUID string
	UserID      uint
}

var errEmailExist = errors.New("email existed")
var errUsernameExist = errors.New("username existed")
var errTokenExpire = errors.New("token expired")
var errInvalidToken = errors.New("invalid token")

//ErrPasswordInvalid error
var ErrPasswordInvalid = errors.New("username and password mismatch")

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

var defaultConfig = &Config{hashPassword, compareHashPassword, "hkhfkalknknvlzaoiis", "hqihoahfonogaosngoa"}

//Auth di
type Auth struct {
	IAuth
	db     *gorm.DB
	claim  IClaimRepository
	config *Config
}

//NewAuth from dependancies
func NewAuth(db *gorm.DB, claim IClaimRepository) IAuth {
	return &Auth{
		db:     db,
		claim:  claim,
		config: defaultConfig,
	}
}

//CreateToken create token
func (auth *Auth) CreateToken(userid uint) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = uuid.NewV4().String()

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(auth.config.AccessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(auth.config.RefreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

//CreateAuth func
func (auth *Auth) CreateAuth(userid uint, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	accessClaim := Claim{td.AccessUUID, userid, &at}
	if err := auth.claim.AddClaim(&accessClaim); err != nil {
		return err
	}

	refreshClaim := Claim{td.RefreshUUID, userid, &rt}
	if err := auth.claim.AddClaim(&refreshClaim); err != nil {
		return err
	}

	return nil
}

//Login user based on their usr and psw, return access token and refresh token
func (auth *Auth) Login(usr string, psw string) (*string, *string, error) {
	account := &Account{Username: usr}
	if err := auth.db.Where(Account{Username: usr}).First(account).Error; err != nil {
		return nil, nil, err
	}
	if err := auth.config.CompareHash(psw, account.PasswordHash); err != nil {
		return nil, nil, ErrPasswordInvalid
	}
	token, err := auth.CreateToken(account.ID)
	auth.CreateAuth(account.ID, token)
	if err != nil {
		return nil, nil, err
	}
	return &token.AccessToken, &token.RefreshToken, nil
}

//Logout user based on their token
func (auth *Auth) Logout(token string) error {
	au, err := auth.ExtractTokenMetadata(token)
	if err != nil {
		return err
	}
	err = auth.claim.RemoveClaim(&Claim{Key: au.AccessUUID})
	return err
	//deleted, err := client.Del(givenUuid).Result()
}

//ExtractTokenMetadata from jwt
func (auth *Auth) ExtractTokenMetadata(tokenString string) (*AccessDetails, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(auth.config.AccessSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		at := time.Unix(claims["exp"].(int64), 0)
		return &AccessDetails{
			AccessUUID: accessUUID,
			UserID:     uint(userID),
			AtExpires:  &at,
		}, nil
	}
	return nil, err
}

//VerifyToken access token. Return error if token is invalid or expired
func (auth *Auth) VerifyToken(tokenString string) (*AccessDetails, error) {
	accessDetail, err := auth.ExtractTokenMetadata(tokenString)
	at := accessDetail.AtExpires
	claim := Claim{accessDetail.AccessUUID, 0, nil}
	if err := auth.claim.GetClaim(&claim); err != nil {
		return nil, err
	}

	//if token is expired, remove it from db
	if at.Before(time.Now()) {
		auth.claim.RemoveClaim(&claim)
		return nil, errTokenExpire
	}
	return accessDetail, err
}

//RefreshToken ask to refresh token. Reture access token and refresh token and error if token is expire or token is invalid
func (auth *Auth) RefreshToken(refreshToken string) (string, string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(auth.config.RefreshSecret), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		return "", "", err
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return "", "", errInvalidToken
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUUID, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			return "", "", errInvalidToken
		}
		userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return "", "", errInvalidToken
		}
		//Delete the previous Refresh Token
		if err := auth.claim.RemoveClaim(&Claim{Key: refreshUUID}); err != nil {
			return "", "", err
		}

		//Create new pairs of refresh and access tokens
		ts, createErr := auth.CreateToken(uint(userID))
		if createErr != nil {
			return "", "", err
		}
		return ts.AccessToken, ts.RefreshToken, nil
	}
	return "", "", err
}

//Register account
func (auth *Auth) Register(account *Account, psw string) error {
	var countUsername, countEmail = 0, 0
	if err := auth.db.Where(&Account{Username: account.Username}).Count(&countUsername).Error; err != nil {
		return err
	}
	if countUsername == 0 {
		return errUsernameExist
	}
	if err := auth.db.Where(&Account{Email: account.Email}).Count(&countEmail).Error; err != nil {
		return err
	}
	if countEmail == 0 {
		return errEmailExist
	}
	if hash, err := auth.config.Hash(psw); err != nil {
		return nil
	} else {
		account.PasswordHash = hash
	}
	if err := auth.db.Create(account).Error; err != nil {
		return err
	}
	return nil
}
