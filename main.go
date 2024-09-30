package main

import (
	"awesomeProject/DB"
	"awesomeProject/imapBrian"
	"awesomeProject/utils"
	"database/sql"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	for {
		runApplication()
		time.Sleep(2 * time.Second)
	}
}

func runApplication() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	emailServer := utils.EmailServer{}
	userCredentials := utils.Login{}
	dbConfig := DB.DBConfig{}
	fileConfig := utils.FileConfig{}
	customColumns := make(map[string]interface{})
	emailDataFields := utils.EmailData{}
	var totalRunTime time.Duration

	imapBrian.Verbose = false
	imapBrian.RetryCount = 1

	startTime := time.Now()
	err := utils.CheckConfig("config/config.xml", &emailServer, &userCredentials, &dbConfig, &customColumns, &emailDataFields, &fileConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	//CREATE DB POOL
	if err := DB.InitDB(dbConfig); err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	defer func(DB *sql.DB) {
		err := DB.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
	}(DB.DB)

	syncMap := mapToSyncMap(customColumns)

	credentials := utils.Credentials{
		ClientID:     userCredentials.ClientId,
		ClientSecret: userCredentials.ClientSecret,
		Scope:        userCredentials.Scope,
		AuthTokenURL: userCredentials.XOauthUrl,
		GrantType:    userCredentials.GrantType,
	}

	downloadPayload := utils.DownloadConfigPayload{
		ServerConfig:    emailServer,
		Credentials:     userCredentials,
		DBConfig:        dbConfig,
		CustomColumns:   syncMap,
		EmailFields:     emailDataFields,
		FileConfig:      fileConfig,
		TokenCredential: credentials,
	}

	downloader := utils.EmailDownloader{
		DownloadPayload: downloadPayload,
	}

	downloader.Start()

	// Calculate the time taken for the loop iteration
	iterationDuration := time.Since(startTime)
	totalRunTime += iterationDuration

	// If the loop iteration took less than 5 seconds, sleep for the remaining time
	if iterationDuration < 5*time.Second {
		time.Sleep(5*time.Second - iterationDuration)
	}
}

func mapToSyncMap(m map[string]interface{}) *sync.Map {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	sm := &sync.Map{}
	for key, value := range m {
		sm.Store(key, value)
	}
	return sm
}
