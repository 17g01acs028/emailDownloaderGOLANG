package utils

import (
	"awesomeProject/DB"
	"awesomeProject/QueryBuilder"
	"awesomeProject/imapBrian"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/emersion/go-imap"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Name struct {
	Space string
	Local string
}
type Attr struct {
	Name  Name
	Value string
}
type EmailServer struct {
	Host          string
	Port          int
	Thread        int
	DownloadLimit int
}
type Login struct {
	Email        string
	Password     string
	TYPE         string
	ClientId     string
	ClientSecret string
	Scope        string
	XOauthUrl    string
	TenantId     string
	GrantType    string
}
type Result struct {
	Count string
	Last  string
	First string
}
type EmailData struct {
	MessageID   string
	MID         string
	SenderName  string
	From        string
	Cc          string
	Bcc         string
	To          string
	Subject     string
	Body        string
	Date        string
	ReplyTo     string
	HtmlBody    string
	TextBody    string
	Attachments string
}
type FileConfig struct {
	Filename string
}

type Mails struct {
	DownloadLimit int
}

func RsaDecrypt(privateKeyPath string, passphrase string, encryptedText string) (string, error) {

	strippedText := strings.ReplaceAll(encryptedText, " ", "")
	// Decode the Base64-encoded encrypted text
	encryptedData, err := base64.StdEncoding.DecodeString(strippedText)
	if err != nil {
		return "", fmt.Errorf("base64 decoding error: %w", err)
	}

	// Read the private key from file
	privPEM, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("error reading private key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Decrypt the PEM block to get the DER encoded private key
	decryptedDER, err := x509.DecryptPEMBlock(block, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("error decrypting PEM block: %w", err)
	}

	// Parse the private key from DER encoding
	privateKey, err := x509.ParsePKCS1PrivateKey(decryptedDER)
	if err != nil {
		return "", fmt.Errorf("error parsing private key: %w", err)
	}

	// Decrypt the data with the private key
	decryptedData, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedData,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("error decrypting data: %w", err)
	}

	return string(decryptedData), nil
}
func RsaEncrypt(publicKeyPath string, clearText string) (string, error) {
	// Convert clearText to byte slice
	plaintext := []byte(clearText)

	// Read the public key from file
	pubPEM, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return "", err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// Type assert the public key to *rsa.PublicKey
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("not RSA public key")
	}

	// Encrypt the data with the public key
	encryptedData, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPub,
		plaintext,
		nil,
	)
	if err != nil {
		return "", err
	}

	// Encode the encrypted data to Base64 for easier display/storage
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	return encodedData, nil
}
func GenerateAndSaveKeys(privateKeyPath, publicKeyPath, passphrase string) error {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Convert the private key to ASN.1 DER encoded form
	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)

	// Encrypt the private key with a passphrase
	encryptedPEMBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		privASN1,
		[]byte(passphrase),
		x509.PEMCipherAES256,
	)
	if err != nil {
		return err
	}

	// Save the encrypted private key to a file
	privPEM := pem.EncodeToMemory(encryptedPEMBlock)
	err = ioutil.WriteFile(privateKeyPath, privPEM, 0600)
	if err != nil {
		return err
	}

	// Convert the public key to PEM string
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	// Save the public key to a file
	err = ioutil.WriteFile(publicKeyPath, pubPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}
func MailServer(server EmailServer) error {
	fmt.Println("\n***********************************************************")
	fmt.Println("Connecting to email server...")
	fmt.Println("***********************************************************")
	fmt.Println("=>SERVER :: " + server.Host + " \n=>PORT :: " + strconv.Itoa(server.Port))

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	//var conn *tls.Conn
	_, err := tls.Dial("tcp", server.Host+":"+strconv.Itoa(server.Port), tlsConfig)

	//serverAddress := server.Host + ":" + strconv.Itoa(server.Port)
	//c, err := client.DialTLS(serverAddress, tlsConfig)

	if err != nil {
		fmt.Println("***********************************************************")
		fmt.Println("Connecting to email server failed")
		fmt.Println("***********************************************************")
		fmt.Println("\n***********************************************************")
		fmt.Println("error " + err.Error())
		fmt.Println("***********************************************************\n")
		return err
	}
	fmt.Println("***********************************************************")
	fmt.Println("Connecting to email server done")
	fmt.Println("***********************************************************")
	return nil
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
func CheckLogins(s EmailServer, credentials Login, crd Credentials) error {
	fmt.Println("\n***********************************************************")
	fmt.Println("Logging to email server...")
	fmt.Println("***********************************************************")

	if strings.ToLower(credentials.TYPE) == "plain_text" {
		im, err := imapBrian.New(credentials.Email, credentials.Password, s.Host, s.Port)
		check(err)
		defer func(im *imapBrian.Dialer) {
			err := im.Close()
			if err != nil {

			}
		}(im)
	} else if strings.ToLower(credentials.TYPE) == "xoauth" {

		for {
			_, err := fetchNewToken(crd)
			if err != nil {
				fmt.Println("Error generating access token, retrying...")
				continue
			}

			//im, err := imapBrian.NewWithOAuth2Copy(credentials.Email, token, s.Host, s.Port)
			//if err != nil {
			//	fmt.Println(err)
			//	continue
			//}
			//defer func(im *imapBrian.Dialer) {
			//	err := im.Close()
			//	if err != nil {
			//		return
			//	}
			//}(im)
			break
		}

	} else {
		fmt.Println(credentials.TYPE)
		panic("Authentication Method not permitted")
	}

	fmt.Println("***********************************************************")
	fmt.Println("Logging to email server succeeded")
	fmt.Println("***********************************************************")
	return nil
}
func LoadXMLFile(path string) (*xmlquery.Node, error) {
	fmt.Println("\n***********************************************************")
	fmt.Println("Loading Config file")
	fmt.Println("***********************************************************")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("\n***********************************************************")
		fmt.Println("Loading Config file failed")
		fmt.Println("***********************************************************")
		fmt.Println("***********************************************************")
		fmt.Println("Error :: " + err.Error())
		fmt.Println("***********************************************************\n")
		return nil, err
	}
	reader := bytes.NewReader(data)
	root, err := xmlquery.Parse(reader)
	if err != nil {
		fmt.Println("\n***********************************************************")
		fmt.Println("Loading Config file failed")
		fmt.Println("***********************************************************")
		fmt.Println("***********************************************************")
		fmt.Println("Error :: " + err.Error())
		fmt.Println("***********************************************************\n")
		return nil, err
	}
	fmt.Println("***********************************************************")
	fmt.Println("Loading Config file succeeded")
	fmt.Println("***********************************************************")
	return root, nil
}
func GetXPathValue(root *xmlquery.Node, xpathExpr string) (string, bool) {
	path := xmlquery.Find(root, xpathExpr)
	if len(path) > 0 {
		return path[0].InnerText(), true
	}
	return "", false
}
func CheckConfig(configPath string, emailServer *EmailServer, userCredentials *Login, dbConfig *DB.DBConfig, customColumns *map[string]interface{}, emailFields *EmailData, fileConfig *FileConfig) error {
	root, err := LoadXMLFile(configPath)
	if err != nil {
		return err
	}

	// Define XPath expressions for each field
	emailXPath := "//APP/USERS/USER/EMAIL"
	passwordXPath := "//APP/USERS/USER/PASSWORD"
	userStatusXPath := "//APP/USERS/USER/STATUS"

	authenticationTypeXPath := "//APP/USERS/USER/AUTHTYPE"
	clientIdXPath := "//APP/USERS/USER/CLIENTID"
	tenantIdXPath := "//APP/USERS/USER/TENANTID"
	clientSecretXPath := "//APP/USERS/USER/CLIENTSECRET"
	grantTypeXPath := "//APP/USERS/USER/GRANTTYPE"
	scopeXPath := "//APP/USERS/USER/SCOPE"
	xAouthtokenUrlXPath := "//APP/USERS/USER/OAUTHTOKENURL"

	// SERVER XPATH
	serverAddressXPath := "//APP/USERS/USER/SERVER/ADDRESS"
	serverPortXPath := "//APP/USERS/USER/SERVER/PORT"
	serverThreadXPath := "//APP/USERS/USER/SERVER/THREAD"
	serverStatusXPath := "//APP/USERS/USER/SERVER/STATUS"

	//// MAILS
	//mailCountXpath := "//USER/MAILS/COUNT"
	//mailInitialCountXpath := "//USER/MAILS/INITIAL_COUNT"
	//mailFirstXpath := "//USER/MAILS/FIRST"
	//mailDownloadLimitXpath := "//USER/MAILS/OLD_MAILS"
	//mailLastXpath := "//USER/MAILS/LAST"

	// INTEGRITY
	integrityHashXpath := "//APP/INTEGRITY/HASH"
	integrityStatusXpath := "//APP/INTEGRITY/STATUS"

	// DATABASE
	databaseNameXpath := "//APP/DATABASE/NAME"
	databaseHostXpath := "//APP/DATABASE/HOST"
	maxConnectionXpath := "//APP/DATABASE/MAXCONNECTIONS"
	databasePortXpath := "//APP/DATABASE/PORT"
	databaseTypeXpath := "//APP/DATABASE/TYPE"
	databaseUserXpath := "//APP/DATABASE/USER"
	databasePasswordXpath := "//APP/DATABASE/PASSWORD"

	// TABLE
	tableNameXpath := "//APP/DATABASE/TABLE/NAME"
	tableStatusXpath := "//APP/DATABASE/TABLE/STATUS"

	// DATABASE STATUS
	databaseStatusXpath := "//APP/DATABASE/STATUS"

	// Extract values using XPath
	email, _ := GetXPathValue(root, emailXPath)
	password, _ := GetXPathValue(root, passwordXPath)

	// SERVER
	serverAddress, _ := GetXPathValue(root, serverAddressXPath)
	serverPort, _ := GetXPathValue(root, serverPortXPath)
	serverThread, _ := GetXPathValue(root, serverThreadXPath)

	// INTEGRITY
	integrityHash, _ := GetXPathValue(root, integrityHashXpath)

	// DATABASE
	databaseName, _ := GetXPathValue(root, databaseNameXpath)
	databaseHost, _ := GetXPathValue(root, databaseHostXpath)
	databasePort, _ := GetXPathValue(root, databasePortXpath)
	databaseType, _ := GetXPathValue(root, databaseTypeXpath)
	maxConnection, _ := GetXPathValue(root, maxConnectionXpath)
	databaseUser, _ := GetXPathValue(root, databaseUserXpath)
	databasePassword, _ := GetXPathValue(root, databasePasswordXpath)

	// TABLE
	tableName, _ := GetXPathValue(root, tableNameXpath)

	//mailDownloadLimit, _ := GetXPathValue(root, mailDownloadLimitXpath)

	//limit, err := strconv.Atoi(mailDownloadLimit)
	//if err != nil {
	//	limit = 1000
	//}

	err = ModifyXML(root, integrityHashXpath, "")
	if err != nil {
		fmt.Println("Error modifying XML:", err)
		return err
	}
	//Check if integrity is ok If not recheck the config and reconfigure
	xml, err := SerializeXML(root)
	if err != nil {
		fmt.Println("Error serializing XML:", err)
		return err
	}

	//Checking and encrypting Email Server Data
	serverPortEncyptedStatus, err := GetAttributeValue(root, serverPortXPath, "encrypted")
	serverHostEncyptedStatus, err := GetAttributeValue(root, serverAddressXPath, "encrypted")

	if serverHostEncyptedStatus == "yes" {
		serverAddress, err = RsaDecrypt("utils/key/key.pem", "steve", serverAddress)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", serverAddress)
		if err != nil {
			return err
		}
		err = ModifyXML(root, serverAddressXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, serverAddressXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if serverPortEncyptedStatus == "yes" {
		serverPort, err = RsaDecrypt("utils/key/key.pem", "steve", serverPort)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", serverPort)
		if err != nil {
			return err
		}
		err = ModifyXML(root, serverPortXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, serverPortXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	//Checking email and password
	clientId, _ := GetXPathValue(root, clientIdXPath)
	clientSecret, _ := GetXPathValue(root, clientSecretXPath)
	scope, _ := GetXPathValue(root, scopeXPath)
	authenticationType, _ := GetXPathValue(root, authenticationTypeXPath)
	grantType, _ := GetXPathValue(root, grantTypeXPath)
	xAouthtokenUrl, _ := GetXPathValue(root, xAouthtokenUrlXPath)
	tenantId, _ := GetXPathValue(root, tenantIdXPath)

	emailEncyptedStatus, err := GetAttributeValue(root, emailXPath, "encrypted")
	passwordEncyptedStatus, err := GetAttributeValue(root, passwordXPath, "encrypted")
	clientIdEncyptedStatus, err := GetAttributeValue(root, clientIdXPath, "encrypted")
	clientSecretEncyptedStatus, err := GetAttributeValue(root, clientSecretXPath, "encrypted")
	scopeEncyptedStatus, err := GetAttributeValue(root, scopeXPath, "encrypted")
	grantTypeEncyptedStatus, err := GetAttributeValue(root, grantTypeXPath, "encrypted")
	xAouthtokenUrlEncyptedStatus, err := GetAttributeValue(root, xAouthtokenUrlXPath, "encrypted")
	tenantIdEncyptedStatus, err := GetAttributeValue(root, tenantIdXPath, "encrypted")

	if emailEncyptedStatus == "yes" {
		email, err = RsaDecrypt("utils/key/key.pem", "steve", email)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", email)
		if err != nil {
			return err
		}
		err = ModifyXML(root, emailXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, emailXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if passwordEncyptedStatus == "yes" {
		password, err = RsaDecrypt("utils/key/key.pem", "steve", password)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", password)
		if err != nil {
			return err
		}
		err = ModifyXML(root, passwordXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, passwordXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if clientIdEncyptedStatus == "yes" {
		clientId, err = RsaDecrypt("utils/key/key.pem", "steve", clientId)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", clientId)
		if err != nil {
			return err
		}
		err = ModifyXML(root, clientIdXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, clientIdXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if clientSecretEncyptedStatus == "yes" {
		clientSecret, err = RsaDecrypt("utils/key/key.pem", "steve", clientSecret)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", clientSecret)
		if err != nil {
			return err
		}
		err = ModifyXML(root, clientSecretXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, clientSecretXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if scopeEncyptedStatus == "yes" {
		scope, err = RsaDecrypt("utils/key/key.pem", "steve", scope)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", scope)
		if err != nil {
			return err
		}
		err = ModifyXML(root, scopeXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, scopeXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if grantTypeEncyptedStatus == "yes" {
		grantType, err = RsaDecrypt("utils/key/key.pem", "steve", grantType)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", grantType)
		if err != nil {
			return err
		}
		err = ModifyXML(root, grantTypeXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, grantTypeXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if xAouthtokenUrlEncyptedStatus == "yes" {
		xAouthtokenUrl, err = RsaDecrypt("utils/key/key.pem", "steve", xAouthtokenUrl)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", xAouthtokenUrl)
		if err != nil {
			return err
		}
		err = ModifyXML(root, xAouthtokenUrlXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, xAouthtokenUrlXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}
	if tenantIdEncyptedStatus == "yes" {
		tenantId, err = RsaDecrypt("utils/key/key.pem", "steve", tenantId)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", tenantId)
		if err != nil {
			return err
		}
		err = ModifyXML(root, tenantIdXPath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, tenantIdXPath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if strings.ToLower(authenticationType) == strings.ToLower("xoauth") || strings.ToLower(authenticationType) == strings.ToLower("plain_text") {

	} else {
		return fmt.Errorf("Error occurred: %s", "This authentication type is not supported.")
	}

	//Checking DB Credentials
	dbNameEncyptedStatus, err := GetAttributeValue(root, databaseNameXpath, "encrypted")
	dbHostEncyptedStatus, err := GetAttributeValue(root, databaseHostXpath, "encrypted")
	dbPortEncyptedStatus, err := GetAttributeValue(root, databasePortXpath, "encrypted")
	dbUserEncyptedStatus, err := GetAttributeValue(root, databaseUserXpath, "encrypted")
	dbPasswordEncyptedStatus, err := GetAttributeValue(root, databasePasswordXpath, "encrypted")

	if dbNameEncyptedStatus == "yes" {
		databaseName, err = RsaDecrypt("utils/key/key.pem", "steve", databaseName)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", databaseName)
		if err != nil {
			return err
		}

		err = ModifyXML(root, databaseNameXpath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, databaseNameXpath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if dbHostEncyptedStatus == "yes" {
		databaseHost, err = RsaDecrypt("utils/key/key.pem", "steve", databaseHost)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", databaseHost)
		if err != nil {
			return err
		}
		err = ModifyXML(root, databaseHostXpath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, databaseHostXpath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if dbPortEncyptedStatus == "yes" {
		databasePort, err = RsaDecrypt("utils/key/key.pem", "steve", databasePort)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", databasePort)
		if err != nil {
			return err
		}
		err = ModifyXML(root, databasePortXpath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, databasePortXpath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if dbUserEncyptedStatus == "yes" {
		databaseUser, err = RsaDecrypt("utils/key/key.pem", "steve", databaseUser)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", databaseUser)
		if err != nil {
			return err
		}
		err = ModifyXML(root, databaseUserXpath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, databaseUserXpath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	if dbPasswordEncyptedStatus == "yes" {
		databasePassword, err = RsaDecrypt("utils/key/key.pem", "steve", databasePassword)
		if err != nil {
			return err
		}
	} else {
		encrypt, err := RsaEncrypt("utils/key/publicKey.pem", databasePassword)
		if err != nil {
			return err
		}
		err = ModifyXML(root, databasePasswordXpath, encrypt)
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = UpdateXMLAttribute(root, databasePasswordXpath, "encrypted", "yes")
		if err != nil {
			fmt.Println("putting attributes:", err)
			return err
		}
	}

	path, _ := GetXPathValue(root, "//APP/ATTACHMENTS/PATH")
	if err != nil {
		return err
	}

	if err := CheckPath(path); err != nil {
		return err
	} else {
		fileConfig.Filename = path
	}
	if GenerateIntegrityHash(xml) != integrityHash {

		fmt.Println("Integrity Check and revalidating file....., This might take a while")

		// Start Email server connection Here
		intServerPort, err := strconv.Atoi(serverPort)
		if err != nil {
			return err
		}
		serverConfig := EmailServer{
			Host: serverAddress,
			Port: intServerPort,
		}
		err = MailServer(serverConfig)
		if err != nil {
			return err
		}
		err = ModifyXML(root, serverStatusXPath, "OK")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}

		// Start Email server connection End
		//Checking and encrypting Email Server Data and checking Connection Ends Here
		//user Credentials
		userCredentials.Email = email
		userCredentials.Password = password
		userCredentials.ClientId = clientId
		userCredentials.TYPE = authenticationType
		userCredentials.ClientSecret = clientSecret
		userCredentials.GrantType = grantType
		userCredentials.TenantId = tenantId
		userCredentials.Scope = scope
		userCredentials.XOauthUrl = xAouthtokenUrl

		credentials := Login{
			Email:    email,
			Password: password,
			TYPE:     authenticationType,
		}

		if strings.ToLower(authenticationType) == "xoauth" {
			credentialsToken := Credentials{
				ClientID:     userCredentials.ClientId,
				ClientSecret: userCredentials.ClientSecret,
				Scope:        userCredentials.Scope,
				AuthTokenURL: userCredentials.XOauthUrl,
				GrantType:    userCredentials.GrantType,
			}
			manager, err := NewTokenManager(credentialsToken)
			if err != nil {
				fmt.Println(err)
			}

			TokenManagerG = manager
			// Get OAuth2 token
			token, err := TokenManagerG.GetToken()
			if err != nil {
				fmt.Println(err)
			}

			userCredentials.Password = token
			credentials.Password = token
			fmt.Println("Token::", token)
		}

		severConfig := EmailServer{
			Host: serverAddress,
			Port: intServerPort,
		}

		if serverAddress == "" || intServerPort == 0 {
			return fmt.Errorf("error Please provide Address and Port")
		} else {
			credentialsToken := Credentials{
				ClientID:     userCredentials.ClientId,
				ClientSecret: userCredentials.ClientSecret,
				Scope:        userCredentials.Scope,
				AuthTokenURL: userCredentials.XOauthUrl,
				GrantType:    userCredentials.GrantType,
			}
			err = CheckLogins(severConfig, credentials, credentialsToken)
			if err != nil {
				return err
			}
		}

		err = ModifyXML(root, userStatusXPath, "OK")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}

		//End Checking email and password

		//Check db
		intDBPort, err := strconv.Atoi(databasePort)
		if err != nil {
			return err
		}
		var maxConnectionInt int

		maxCon, err := strconv.Atoi(maxConnection)
		if err != nil {
			maxConnectionInt = 10
		}

		if maxCon < 1 {
			maxConnectionInt = 10
		}

		dbConfig := DB.DBConfig{
			DBType:         databaseType,
			User:           databaseUser,
			Password:       databasePassword,
			DBName:         databaseName,
			Host:           databaseHost,
			Port:           intDBPort,
			MaxConnections: maxConnectionInt,
		}

		db, err := DB.TestConnection(dbConfig)
		if err != nil {
			return err
		}
		defer func(db *sql.DB) {
			err := db.Close()
			if err != nil {

			}
		}(db)

		err = ModifyXML(root, databaseStatusXpath, "OK")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}

		//Checking DB Credentials ENDS Here

		qb := QueryBuilder.NewQueryBuilder1(db, dbConfig.DBType)

		columns, err := qb.GetColumnNames(tableName)
		if err != nil {
			log.Fatalf("Error retrieving column names: %v", err)
		}

		fields := xmlquery.Find(root, "//FIELDS/*")

		for _, field := range fields {
			if field.Data == "CUSTOM" {
				customFields := xmlquery.Find(field, "FIELD")
				for _, customField := range customFields {
					nameAttr := customField.SelectAttr("name")
					if contains(columns, nameAttr) {
						path := GenerateXPath(customField)
						err := UpdateXMLAttribute(root, path, "mapped", "yes")
						if err != nil {
							fmt.Println("Error updating XML attribute:", err)
							return err
						}
					} else {
						path := GenerateXPath(customField)
						err := UpdateXMLAttribute(root, path, "mapped", "no")
						if err != nil {
							fmt.Println("Error updating XML attribute:", err)
							return err
						}
					}
				}
			} else {
				value := field.InnerText()
				if contains(columns, value) {
					// Generate XPath for the field
					path := GenerateXPath(field)
					err := UpdateXMLAttribute(root, path, "mapped", "yes")
					if err != nil {
						fmt.Println("Error updating XML attribute:", err)
						return err
					}
				} else {
					path := GenerateXPath(field)
					err := UpdateXMLAttribute(root, path, "mapped", "no")
					if err != nil {
						fmt.Println("Error updating XML attribute:", err)
						return err
					}
				}
			}
		}

		err = ModifyXML(root, tableStatusXpath, "OK")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}

		//MODIFICATION END
		//DON'T TOUCH ANYTHING AFTER THIS
		err = ModifyXML(root, integrityHashXpath, "")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		// Output the modified XML
		modifiedXML, err := SerializeXML(root)
		if err != nil {
			fmt.Println("Error serializing XML:", err)
			return err
		}

		err = ModifyXML(root, integrityHashXpath, GenerateIntegrityHash(modifiedXML))
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}
		err = ModifyXML(root, integrityStatusXpath, "OK")
		if err != nil {
			fmt.Println("Error modifying XML:", err)
			return err
		}

		// Output the modified XML
		modifiedXML, err = SerializeXML(root)
		if err != nil {
			fmt.Println("Error serializing XML:", err)
			return err
		}

		err = SaveXMLToFile(modifiedXML, configPath)
		if err != nil {
			fmt.Println("Error saving XML to file:", err)
			return err
		}
	}

	threadCount, err := strconv.Atoi(serverThread)
	if err != nil {
		threadCount = 10
	}

	//email credential
	emailServer.Host = serverAddress
	emailServer.Port, err = strconv.Atoi(serverPort)
	emailServer.Thread = threadCount
	if err != nil {
		return err
	}

	var maxConnectionInt int

	maxCon, err := strconv.Atoi(maxConnection)
	if err != nil {
		maxConnectionInt = 10
	}

	if maxCon < 1 {
		maxConnectionInt = 10
	} else {
		maxConnectionInt = maxCon
	}

	//DBCredentials
	dbConfig.Password = databasePassword
	dbConfig.Host = databaseHost
	dbConfig.Port, err = strconv.Atoi(databasePort)
	if err != nil {
		return err
	}
	dbConfig.DBName = databaseName
	dbConfig.User = databaseUser
	dbConfig.DBType = databaseType
	dbConfig.Table = tableName
	dbConfig.MaxConnections = maxConnectionInt

	//Login values
	userCredentials.Email = email
	userCredentials.Password = password
	userCredentials.ClientId = clientId
	userCredentials.TYPE = authenticationType
	userCredentials.ClientSecret = clientSecret
	userCredentials.GrantType = grantType
	userCredentials.TenantId = tenantId
	userCredentials.Scope = scope
	userCredentials.XOauthUrl = xAouthtokenUrl

	//feed custom field
	fields := xmlquery.Find(root, "//FIELDS/*")
	for _, field := range fields {
		if field.Data == "CUSTOM" {
			customFields := xmlquery.Find(field, "FIELD")
			for _, customField := range customFields {
				nameAttr := customField.SelectAttr("name")
				mappedAttr := customField.SelectAttr("mapped")
				if mappedAttr == "yes" {
					// Use the nameAttr as the key and the node's value as the value in the map
					(*customColumns)[nameAttr] = customField.InnerText()
				}
			}
		}
	}

	//GET table fields XPATH

	xpaths := map[string]string{
		"messageID":   "//FIELDS/MESSAGEID",
		"senderName":  "//FIELDS/SENDERNAME",
		"mID":         "//FIELDS/MID",
		"from":        "//FIELDS/FROM",
		"to":          "//FIELDS/TO",
		"cc":          "//FIELDS/CC",
		"bcc":         "//FIELDS/BCC",
		"subject":     "//FIELDS/SUBJECT",
		"date":        "//FIELDS/DATE",
		"replyTo":     "//FIELDS/REPLYTO",
		"htmlBody":    "//FIELDS/HTMLBODY",
		"textBody":    "//FIELDS/TEXTBODY",
		"attachments": "//FIELDS/ATTACHMENTS",
		"custom":      "//FIELDS/CUSTOM",
	}
	for field, xpath := range xpaths {
		mapped, err := GetAttributeValue(root, xpath, "mapped")
		if err != nil {
			fmt.Println("Error fetching attribute value:", err)
			continue
		}

		var value string
		if mapped == "yes" {
			value, _ = GetXPathValue(root, xpath)

			if err != nil {
				fmt.Println("Error fetching element value:", err)
				value = ""
			}
		} else {
			value = ""
		}

		// Assign the value to the appropriate struct field
		switch field {
		case "messageID":
			emailFields.MessageID = value
		case "senderName":
			emailFields.SenderName = value
		case "mID":
			emailFields.MID = value
		case "to":
			emailFields.To = value
		case "cc":
			emailFields.Cc = value
		case "from":
			emailFields.From = value
		case "bcc":
			emailFields.Bcc = value
		case "subject":
			emailFields.Subject = value
		case "date":
			emailFields.Date = value
		case "replyTo":
			emailFields.ReplyTo = value
		case "htmlBody":
			emailFields.HtmlBody = value
		case "textBody":
			emailFields.TextBody = value
		case "attachments":
			emailFields.Attachments = value
		}

	}

	return nil
}
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
func maskEntireString(s string, maskChar rune) string {
	return strings.Repeat(string(maskChar), len(s))
}
func maskCenterString(s string, maskChar rune) string {
	length := len(s)
	if length <= 2 {
		return s // If the string is too short, return it as is
	}

	start := s[:2]
	end := s[length-2:]
	middle := strings.Repeat(string(maskChar), length-2)

	return start + middle + end
}
func ModifyXML(doc *xmlquery.Node, path string, value string) error {
	// Find the node using XPath
	nodes := xmlquery.Find(doc, path)
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes found for XPath: %s", path)
	}

	// Modify the first matching node's content
	node := nodes[0]
	if node.FirstChild != nil && node.FirstChild.Type == xmlquery.TextNode {
		node.FirstChild.Data = value
	} else {
		// If there's no text node, create one and add it as a child
		newText := &xmlquery.Node{
			Type: xmlquery.TextNode,
			Data: value,
		}
		node.FirstChild = newText
	}

	return nil
}
func SerializeXML(doc *xmlquery.Node) (string, error) {
	return doc.OutputXML(true), nil
}
func UpdateXMLAttribute(doc *xmlquery.Node, path string, attrName string, value string) error {
	// Find the node using XPath
	nodes := xmlquery.Find(doc, path)
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes found for XPath: %s", path)
	}

	node := nodes[0]

	// Update the attribute value
	for i, attr := range node.Attr {
		if attr.Name.Local == attrName {
			node.Attr[i].Value = value
			return nil
		}
	}

	return nil
}
func GenerateIntegrityHash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
func VerifyIntegrityHash(input, hash string) bool {
	computedHash := GenerateIntegrityHash(input)
	return computedHash == hash
}
func SaveXMLToFile(xmlContent, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(xmlContent)
	if err != nil {
		return err
	}

	return nil
}
func GetAttributeValue(doc *xmlquery.Node, xpath string, attrName string) (string, error) {
	// Find the node using XPath
	node := xmlquery.FindOne(doc, xpath)
	if node == nil {
		return "", fmt.Errorf("node not found for XPath: %s", xpath)
	}

	// Retrieve the attribute value
	attr := node.SelectAttr(attrName)
	if attr == "" {
		return "", fmt.Errorf("attribute %s not found for XPath: %s", attrName, xpath)
	}

	return attr, nil
}
func ColumnExists(columnMap map[string]bool, columnName string) (bool, error) {
	if columnMap == nil {
		return false, fmt.Errorf("column map cannot be nil")
	}

	_, exists := columnMap[columnName]
	return exists, nil
}
func GenerateXPath(node *xmlquery.Node) string {
	var path string
	for n := node; n != nil && n.Type != xmlquery.DocumentNode; n = n.Parent {
		index := 1
		for sib := n.PrevSibling; sib != nil; sib = sib.PrevSibling {
			if sib.Data == n.Data {
				index++
			}
		}
		path = fmt.Sprintf("/%s[%d]%s", n.Data, index, path)
	}
	return path
}
func NormalizePath(path string) string {
	// Convert all backslashes to slashes
	path = filepath.ToSlash(path)
	// Clean the path to resolve things like `//`, `/./`, `/../` etc.
	return filepath.Clean(path)
}
func CheckPath(path string) error {
	// Normalize the path to handle mixed separators and other oddities
	normalizedPath := NormalizePath(path)

	// Check if the path exists
	info, err := os.Stat(normalizedPath)
	if os.IsNotExist(err) {
		// If the path does not exist, try creating the directory
		if err := os.MkdirAll(normalizedPath, os.ModePerm); err != nil {
			return fmt.Errorf("invalid path, and failed to create directory: %v", err)
		}
		fmt.Println("Directory did not exist, so it was created:", normalizedPath)
	} else if err != nil {
		return fmt.Errorf("error checking the path: %v", err)
	}

	// Check if the path is a directory
	if info != nil && !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	// Check if the path is writable by attempting to create a temp file
	tempFile, err := os.CreateTemp(normalizedPath, "temp")
	if err != nil {
		return fmt.Errorf("path is not writable: %v", err)
	}
	tempFile.Close()

	// Clean up the temp file
	os.Remove(tempFile.Name())

	return nil
}
func formatIMAPAddressList(addresses []*imap.Address) string {
	var formattedAddresses []string
	for _, addr := range addresses {
		formattedAddresses = append(formattedAddresses, fmt.Sprintf("%s <%s>", addr.PersonalName, addr.MailboxName+"@"+addr.HostName))
	}
	return strings.Join(formattedAddresses, ", ")
}
func (d *EmailDownloader) CheckInternetConnectivity(done chan bool) {
	for {
		address := fmt.Sprintf("%s:%d", d.DownloadPayload.ServerConfig.Host, d.DownloadPayload.ServerConfig.Port)

		_, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			fmt.Println("Internet connection lost, retrying...")
			time.Sleep(5 * time.Second)
			continue
		}
		fmt.Println("Internet connection restored.")
		done <- true
		return
	}
}
func saveAttachment(emailID int, filename string, body io.Reader, path string) error {
	// Save attachment to a file (for example)
	messageID := fmt.Sprintf("{[%d]}%s", emailID, filename)
	filePath := path + "/" + messageID
	file, err := os.Create(filePath)
	if err != nil {
		log.Printf("Error creating attachment file %s: %v", filePath, err)
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, body); err != nil {
		log.Printf("Error saving attachment %s: %v", filePath, err)
		return err
	}
	return nil
}
func EmailAddressesToStr(ea imapBrian.EmailAddresses) string {
	var addresses []string
	for name, address := range ea {
		if name != "" {
			addresses = append(addresses, fmt.Sprintf("%s <%s>", name, address))
		} else {
			addresses = append(addresses, address) // No name, just append the email
		}
	}
	return strings.Join(addresses, ", ")
}

func getUUID() string {
	return uuid.New().String()
}

// Utility function: Get current timestamp
func getTimestamp() string {
	return fmt.Sprint(time.Now().Unix())
}

// Replace variables and evaluate conditions
func evaluateCustomField(expr string, emailFields map[string]string) (string, error) {
	// Replace predefined utility functions
	expr = strings.ReplaceAll(expr, "{UUID}", getUUID())
	expr = strings.ReplaceAll(expr, "{TIMESTAMP}", getTimestamp())

	// Handle time format: {TIME:format}
	timeRe := regexp.MustCompile(`\{TIME:([^\}]+)\}`)
	expr = timeRe.ReplaceAllStringFunc(expr, func(match string) string {
		format := timeRe.FindStringSubmatch(match)[1]
		return time.Now().Format(format)
	})

	var dateError string

	// Handle custom dates and date modifiers
	dateRe := regexp.MustCompile(`Date\(([^\)]+)\)(\.innext\(\d+\))?(\.inback\(\d+\))?(\.today)?(\.format\(([^\)]+)\))?`)
	expr = dateRe.ReplaceAllStringFunc(expr, func(match string) string {
		formattedDate, err := handleDateModifiers(match)
		if err != nil {
			dateError = err.Error()
		}
		return formattedDate
	})

	if len(dateError) > 1 {
		return "", fmt.Errorf("missing fields: %v", dateError)
	}

	// Handle field references: {{FIELD_NAME}}
	if emailFields != nil {
		fieldRe := regexp.MustCompile(`\{\{([^\}]+)\}\}`)
		missingFields := []string{}
		expr = fieldRe.ReplaceAllStringFunc(expr, func(match string) string {
			field := fieldRe.FindStringSubmatch(match)[1]
			value, exists := emailFields[field]
			if !exists {
				// Collect missing fields to report errors later
				missingFields = append(missingFields, field)
				return "" // Use empty string here or a placeholder if needed
			}
			return value
		})

		// If there are missing fields, return an error
		if len(missingFields) > 0 {
			return "", fmt.Errorf("missing fields: %v", missingFields)
		}
	} else {
		// Check for field references without emailFields
		placeholdersRe := regexp.MustCompile(`\{\{([^\}]+)\}\}`)
		if placeholdersRe.FindStringIndex(expr) != nil {
			return "", errors.New("expression contains field references but emailFields is not provided")
		}
	}

	// Handle if conditions: {if (condition) {true} else {false}}
	ifRe := regexp.MustCompile(`\{if \(([^)]+)\) \{([^\}]+)\} else \{([^\}]+)\}\}`)
	expr = ifRe.ReplaceAllStringFunc(expr, func(match string) string {

		fmt.Println("If Found ", expr)
		condition := ifRe.FindStringSubmatch(match)[1]
		trueVal := ifRe.FindStringSubmatch(match)[2]
		falseVal := ifRe.FindStringSubmatch(match)[3]

		fmt.Println("Condition ", condition)
		fmt.Println("True val  ", trueVal)
		fmt.Println("False Val ", falseVal)

		if evaluateCondition(condition) {
			return trueVal
		} else {
			return falseVal
		}
	})

	return expr, nil
}

// Evaluate simple conditions (only basic == and != for this example)
func evaluateCondition(cond string) bool {
	cond = strings.TrimSpace(cond)
	if strings.Contains(cond, "==") {
		parts := strings.Split(cond, "==")
		return strings.TrimSpace(parts[0]) == strings.TrimSpace(parts[1])
	} else if strings.Contains(cond, "!=") {
		parts := strings.Split(cond, "!=")
		return strings.TrimSpace(parts[0]) != strings.TrimSpace(parts[1])
	}
	return false
}

// Handle date modifiers (e.g., .innext(7), .inback(7), .today, .format())
func handleDateModifiers(dateStr string) (string, error) {
	now := time.Now()
	dateFormatRe := regexp.MustCompile(`Date\(([^\)]*)\)`)
	formatRe := regexp.MustCompile(`\.format\(([^\)]+)\)`)
	dateMatches := dateFormatRe.FindStringSubmatch(dateStr)
	formatMatches := formatRe.FindStringSubmatch(dateStr)

	var date time.Time
	var dateFormat string

	// Determine the base date
	if len(dateMatches) > 1 {
		dateStrPart := dateMatches[1]
		if dateStrPart == "today" || dateStrPart == "" {
			date = now
		} else {
			// Try both date-only and date-time formats
			dateFormats := []string{
				"02-01-2006 15:04:05",  // DD-MM-YYYY HH:MM:SS
				"01-02-2006 15:04:05",  // MM-DD-YYYY HH:MM:SS
				"2006-01-02 15:04:05",  // YYYY-MM-DD HH:MM:SS
				"02/01/2006 15:04:05",  // DD/MM/YYYY HH:MM:SS
				"01/02/2006 15:04:05",  // MM/DD/YYYY HH:MM:SS
				"2006/01/02 15:04:05",  // YYYY/MM/DD HH:MM:SS
				"2006.01.02 15:04:05",  // YYYY.MM.DD HH:MM:SS
				"02.01.2006 15:04:05",  // DD.MM.YYYY HH:MM:SS
				"2006-01-02T15:04:05Z", // YYYY-MM-DDTHH:MM:SSZ
				"2006-01-02T15:04:05",  // YYYY-MM-DDTHH:MM:SS
				"02-01-2006",           // DD-MM-YYYY
				"01-02-2006",           // MM-DD-YYYY
				"2006-01-02",           // YYYY-MM-DD
				"02/01/2006",           // DD/MM/YYYY
				"01/02/2006",           // MM/DD/YYYY
				"2006/01/02",           // YYYY/MM/DD
				"2006.01.02",           // YYYY.MM.DD
				"02.01.2006",           // DD.MM.YYYY
				"15:04:05",             // HH:MM:SS
				"03:04 PM",             // HH:MM AM/PM       // Date Only
			}
			var err error
			for _, format := range dateFormats {
				date, err = time.Parse(format, dateStrPart)
				if err == nil {
					break
				}
			}
			if err != nil {
				return "", fmt.Errorf("invalid date format: %s", dateStrPart)
			}
		}
	} else if strings.Contains(dateStr, "today") {
		date = now
	} else {
		return "", fmt.Errorf("date not found in: %s", dateStr)
	}

	// Apply date modifiers
	if strings.Contains(dateStr, ".innext(") {
		daysStr := extractModifierValue(dateStr, "innext")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return "", fmt.Errorf("invalid number of days: %s", daysStr)
		}
		date = date.AddDate(0, 0, days)
	}

	if strings.Contains(dateStr, ".inback(") {
		daysStr := extractModifierValue(dateStr, "inback")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return "", fmt.Errorf("invalid number of days: %s", daysStr)
		}
		date = date.AddDate(0, 0, -days)
	}

	// Determine the date format
	if len(formatMatches) > 1 {
		dateFormat = formatMatches[1]
		_, err := time.Parse(dateFormat, date.Format(dateFormat))
		if err != nil {
			dateFormat = "02-01-2006"
		}
	} else {
		dateFormat = "02-01-2006" // Default format
	}

	// Format the date and return
	return date.Format(dateFormat), nil
}

// Extract the modifier value (e.g., 7 from .innext(7))
func extractModifierValue(dateStr, modifier string) string {
	re := regexp.MustCompile(fmt.Sprintf(`\.%s\((\d+)\)`, modifier))
	matches := re.FindStringSubmatch(dateStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}
