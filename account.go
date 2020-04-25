package auth

import (
	"github.com/jinzhu/gorm"
	"github.com/thanhtuan260593/auth/models"
)

//AccountRepository implement IAccountRepository, require dependancies: gorm.DB
type AccountRepository struct {
	IAccountRepository
	db *gorm.DB
}

//Get new account implement based on non zero properties on account
func (r *AccountRepository) Get(account *models.Account) error {
	return nil
}

//Update an account implement
func (r *AccountRepository) Update(account *models.Account) error {
	return nil
}

//Add an account implement
func (r *AccountRepository) Add(account *models.Account) error {
	return nil
}

//Exist with condition
func (r *AccountRepository) Exist(account *models.Account) (bool, error) {
	return true, nil
}
