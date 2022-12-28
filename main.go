package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"unicode"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var db *sql.DB

var store = sessions.NewCookieStore([]byte("super-secret-password"))

// the main function. Establishes connection to Databse and the Handlers for the other pages
// Handlers handle the specific instance they are assigned to . For example: the addItemHandler is assigned to /addItem
// So when someone visits the address "localhost:8080/addItem", the function add Item handler is called and it handles that page
func main() {

	// loads the html pages aka templates into the tpl variable
	//templats are stored int he templates folder
	tpl, _ = template.ParseGlob("templates/*html")
	var err error

	//establishes connection to the database
	// in the string "root:password@tcp(localhost:3306)/testdb" the term "password" is your actual password to the mysql workbench
	//if your password was cheeseburger the string would look like this root:cheeseburger@tcp(localhost:3306)/testdb
	// the term "testdb" is the name of the databse you are trying to connect to
	db, err = sql.Open("mysql", "root:4myfamilyItryit@tcp(localhost:3306)/testdb")

	if err != nil {
		panic(err.Error())

	}
	//defers the closing of the databse connection till later. this you will see throughout the program
	defer db.Close()

	//these establishes the handler functions for each specific address
	http.HandleFunc("/addItem", addItemHandler)
	http.HandleFunc("/registerItemHandler", registerItemHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/loginauth", loginAuthHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/registerauth", registerAuthHandler)
	http.HandleFunc("/about", Auth(aboutHandler))
	http.HandleFunc("/", Auth(indexHandler))
	http.ListenAndServe("localhost:8080", context.ClearHandler(http.DefaultServeMux))

}

func Auth(HandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		_, ok := session.Values["userID"]
		if !ok {
			http.Redirect(w, r, "/login", 302)
			return
		}

		HandlerFunc.ServeHTTP(w, r)
	}

}

// handler for the /addItem page
func addItemHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("***** itemAdd is running")
	tpl.ExecuteTemplate(w, "addItem.html", nil)

}

// handler for /registerItemHandler, parses the form from /addItem then adds it to the databse
func registerItemHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("****** item auth is running")

	//parses the information
	r.ParseForm()

	//load item description into the database
	name := r.FormValue("name")
	description := r.FormValue("description")
	quantity := r.FormValue("quantity")

	fmt.Println("**************************************************")
	fmt.Println("name: ", name)
	fmt.Println("description: ", description)
	fmt.Println("quantity : ", quantity)
	fmt.Println("***************************************************")

	var insertStmt *sql.Stmt

	var result sql.Result
	var err error

	//initialize of the SQL statement, the (?,?,?) will be filled in the next line
	insertStmt, err = db.Prepare("INSERT INTO inventory (name,description,quantity) VALUES(?,?,?);")

	//executes SQL statement replaces (?,?,?) with (name, description,quantity)
	result, err = insertStmt.Exec(name, description, quantity)

	//error checks, will only trigger sql fails
	if err != nil {
		fmt.Println("error preparing staetment:", err)
		tpl.ExecuteTemplate(w, "addItem.html", "there was a problem adding item")
		return

	}

	//prints out sql data , primarily used for checking if it added correctly. this section will be deleted later just useful for development
	rowsAff, _ := result.RowsAffected()
	lastIns, _ := result.LastInsertId()

	fmt.Println("rowsAff: ", rowsAff)
	fmt.Println("lastINs:", lastIns)
	fmt.Println("err", err)
	fmt.Println("result", result)
	//if err != nil {
	//	fmt.Println("error inserting new user")
	//}
	defer insertStmt.Close()

	tpl.ExecuteTemplate(w, "registerItemAuth.html", nil)

}

//handles logging out

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("******* logoutHandler running ******")
	session, _ := store.Get(r, "session")

	delete(session.Values, "userID")
	session.Save(r, w)
	tpl.ExecuteTemplate(w, "login.html", "Logged Out")

}

//unfinished so far, will eventually handle the /index page aka the base page of the website

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("****** indexHandler running *********")
	tpl.ExecuteTemplate(w, "index.html", "Logged In")
}

// unfinished so far, will eventually handle the about page possibly get rid of this one undecided atm
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("******* aboutHandler running*******")
	tpl.ExecuteTemplate(w, "about.html", "Logged In")
}

// handles the login page
func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("******** loginHanlder is running ************")
	tpl.ExecuteTemplate(w, "login.html", nil)

}

// handles verifying that the login information is correct, and then logs in the user
func loginAuthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("********* loginAuthHandler running*********")

	//gets login information from user and stores it in local variables
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	fmt.Println("username:", username, "password:", password)

	var userID, hash string

	//queries the database for the specific username
	stmt := "SELECT Hash FROM bcrypt Where Username = ?"
	row := db.QueryRow(stmt, username)

	//selects the hashed password for the username and throws and error if it does not exist
	err := row.Scan(&hash)
	fmt.Println("hash from db:", hash)
	if err != nil {
		fmt.Println("error Selecting Hash in db by Username")
		tpl.ExecuteTemplate(w, "login.html", "check username and password")
		return
	}

	//compares the hash on the db to the hashed password submitted by the user
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	//if the hashes match each other, logs the user in, else it retursn them to the login screen
	//also creates the session cookie for the user upon logging in
	if err == nil {

		session, _ := store.Get(r, "session")
		session.Values["userID"] = userID
		session.Save(r, w)
		tpl.ExecuteTemplate(w, "index.html", "Logged IN")

		return
	}

	//returns the user to the login screen because there was a probelm with the credentials they submitted
	fmt.Println("incorrect password and or username")
	tpl.ExecuteTemplate(w, "login.html", "check username and password")

}

// handles the registration for new user page
func registerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("registerHandler running")
	tpl.ExecuteTemplate(w, "register.html", nil)

}

//to do list
//create inventory databse
//register emails
//email recovery
//email authentication
// hash the rest of the information of the user "name, address, any personal information"
//change db password to a system variable

// registers a new user, checks to see if the password and username are valid and available, will throw error if otheriwse
// will check the password and username against various booleans. If all booleans are true then the password and username is valid if any are false
// the registration will fail
func registerAuthHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Println("register Auth Handler is running ****")
	//gets registration form information from user
	r.ParseForm()

	//loads the username data into the variable username
	username := r.FormValue("username")

	var nameAlphaNumeric = true

	//checks to see if the username is only alphanumeric characters
	for _, char := range username {

		if unicode.IsLetter(char) == false && unicode.IsNumber(char) == false {
			nameAlphaNumeric = false
		}
	}

	var nameLength bool

	//checks to see if the username is of the appropriate length

	if 5 <= len(username) && len(username) <= 50 {
		nameLength = true
	}

	password := r.FormValue("password")

	fmt.Println("password:", password, "\npswdLength:", len(password))

	var pswdLowercase, pswdUppercase, pswdNumber, pswdSpecial, pswdLength, pswdNoSpaces bool
	pswdNoSpaces = true

	//checks the password for lower case, u pper case, number, symobl and spaces
	//will swithc the boolean to true if any case is detected
	//will switch the boolean to false if a space is detected

	for _, char := range password {
		switch {

		case unicode.IsLower(char):
			pswdLowercase = true

		case unicode.IsUpper(char):
			pswdUppercase = true
		case unicode.IsNumber(char):
			pswdNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			pswdSpecial = true

		case unicode.IsSpace(int32(char)):
			pswdNoSpaces = false

		}

	}

	//checks the password for its length requirements
	if 11 < len(password) && len(password) < 60 {
		pswdLength = true
	}

	fmt.Println("pswdLowercase:", pswdLowercase, "\npswdUppercase:", pswdUppercase, "\npswdNumber:", pswdNumber, "\npsSymbol:", pswdSpecial, "\nnameLength:", nameLength, "\nalphaNumeric:", nameAlphaNumeric, "\nnameSpaces", pswdNoSpaces, "\npswdLenght:", pswdLength)

	//checks the booleans to see if the password and username fit all requirements. If all booleans are true then the password and username is valid
	//if a single boolean is false then the password username combo is invalid for some reason.
	if !pswdLowercase || !pswdUppercase || !pswdNumber || !pswdSpecial || !pswdLength || !pswdNoSpaces || !nameAlphaNumeric || !nameLength {
		tpl.ExecuteTemplate(w, "register.html", "please check username and password criteria")
		fmt.Println("User Registration failed")
		return

	}

	//initializes the sql statement
	stmt := "Select UserID FROM bcrypt WHERE username = ?"

	row := db.QueryRow(stmt, username)
	var uID string
	err := row.Scan(&uID)

	//throws error if the username already exists
	if err != sql.ErrNoRows {
		fmt.Println("username already exists,err:", err)
		tpl.ExecuteTemplate(w, "register.html", "username already taken")

		return
	}

	var hash []byte

	//generates hash for password
	hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	//throws error if there was a problem hashing password
	if err != nil {
		fmt.Println("brcypt err:", err)
		tpl.ExecuteTemplate(w, "register.html", "there was a problem registering account")
		return
	}

	fmt.Println("hash:", hash)
	fmt.Println("string(hash):", string(hash))

	var insertStmt *sql.Stmt

	//initializes sql statement to add new username,password combo
	insertStmt, err = db.Prepare("INSERT INTO bcrypt (Username,Hash) VALUES(?,?);")

	//throws error if there was an error in preparing the statement
	if err != nil {
		fmt.Println("error preparing staetment:", err)
		tpl.ExecuteTemplate(w, "register.html", "there was a problem registering account")
		return

	}

	//closes the connection later
	defer insertStmt.Close()
	var result sql.Result

	//executes previously initialized sql statement
	result, err = insertStmt.Exec(username, hash)

	//the following lines are sql information useful for development but will be deleted later. They are simple print checks
	rowsAff, _ := result.RowsAffected()
	lastIns, _ := result.LastInsertId()

	fmt.Println("rowsAff: ", rowsAff)
	fmt.Println("lastINs:", lastIns)
	fmt.Println("err", err)
	fmt.Println("result", result)
	if err != nil {
		fmt.Println("error inserting new user")
	}

}
