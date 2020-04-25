package auth

import "github.com/thanhtuan260593/auth/models"

//IClaimRepository db function
type IClaimRepository interface {
	AddClaim(*models.Claim) error
	RemoveClaim(*models.Claim) error
	GetClaim(*models.Claim) error
}

//IAccountRepository interface
type IAccountRepository interface {
	Get(*models.Account) error
	Add(*models.Account) error
	Update(*models.Account) error
	Exist(*models.Account) (bool, error)
}

//IAuth interface
type IAuth interface {
	//Login user based on their usr and psw, return access token and refresh token
	Login(usr string, psw string) (*string, *string, error)
	//Logout user based on their token
	Logout(token string) error
	//VerifyToken access token. Return error if token is invalid or expired
	VerifyToken(token string) (*models.AccessDetails, error)
	//RefreshToken ask to refresh token. Reture access token and refresh token and error if token is expire or token is invalid
	RefreshToken(token string) (string, string, error)
	//Register account
	Register(*models.Account, string) error
}
