package utils

import (
	"awesomeProject/DB"
	"awesomeProject/QueryBuilder"
	"awesomeProject/imapBrian"
	"bytes"
	"container/heap"
	"database/sql"
	"encoding/json"
	"fmt"
	imapB "github.com/BrianLeishman/go-imap"
	"log"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

var initialValuesToQueue sync.Once

type EmailStatus struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	ErrorMsg string `json:"error_msg"`
}
type AttachmentInfo struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	MimeType string `json:"mime_type"`
}
type DownloadConfigPayload struct {
	ServerConfig    EmailServer
	Credentials     Login
	DBConfig        DB.DBConfig
	CustomColumns   *sync.Map
	EmailFields     EmailData
	FileConfig      FileConfig
	TokenCredential Credentials
}
type New struct {
	ID int32
}

type Email struct {
	ID       int
	Priority int
}

// EmailPriorityQueue implements a priority queue for Emails.
type EmailPriorityQueue []*Email

// Implement heap.Interface
func (pq EmailPriorityQueue) Len() int { return len(pq) }
func (pq EmailPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	return pq[i].Priority > pq[j].Priority
}
func (pq EmailPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}
func (pq *EmailPriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*Email))
}
func (pq *EmailPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

type EmailDownloader struct {
	emailQueue        EmailPriorityQueue
	mu                sync.Mutex
	DownloadPayload   DownloadConfigPayload
	wg                sync.WaitGroup
	cond              *sync.Cond
	downloadingEmails sync.Map
	newMails          sync.Map
}

func (d *EmailDownloader) checkForNewEmails() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	for {

		fmt.Println("\n***********************************************************")
		fmt.Println("Checking for undownloaded mails...")
		fmt.Println("***********************************************************")

		im := d.im()

		defer im.Close()

		err := im.SelectFolder("INBOX")

		if err != nil {
			continue
		}
		//check(err)

		qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
		query, values, err := qb.BuildCountQuery("mail.tracker_table", nil)
		if err != nil {
			fmt.Println("Error building count query...")
			continue
		}

		db := DB.DB

		tx, err := db.Begin()
		if err != nil {
			fmt.Println("Error starting transaction...")
			continue
		}

		var count int
		err = tx.QueryRow(query, values...).Scan(&count)
		if err != nil {
			fmt.Println("Error running select query...")
			err := tx.Rollback()
			if err != nil {
				return
			}
			continue
		}

		err = tx.Commit()
		if err != nil {
			err := tx.Rollback()
			if err != nil {
				return
			}
			continue
		}

		if count == 0 {
			batchSize := 1000
			seqNums, err := im.GetUIDs("ALL")
			if err != nil {
				fmt.Println("Error searching emails:", err)
				//continue
			}

			columns := []string{"email_id", "priority", "status_name", "status_date", "date_created"}
			for i := 0; i < len(seqNums); i += batchSize {
				txInner, err := db.Begin()
				if err != nil {
					fmt.Println("Error starting transaction...")
					continue
				}
				end := i + batchSize
				if end > len(seqNums) {
					end = len(seqNums)
				}
				batch := seqNums[i:end]
				now := time.Now()
				formattedTime := now.Format("2006-01-02 15:04:05")

				var rows [][]interface{}
				for _, email := range batch {
					emailIDStr := fmt.Sprintf("%d", email)
					row := []interface{}{emailIDStr, emailIDStr, "undownloaded", formattedTime, formattedTime}
					rows = append(rows, row)
				}

				query, values, err := qb.BuildInsertBatchQuery("mail.tracker_table", columns, rows)
				if err != nil {
					fmt.Println("Error building query:", err)
					return
				}

				// Execute the query
				_, err = txInner.Exec(query, values...)
				if err != nil {
					fmt.Println("Error executing query in check mail undowloaded:", err)
					return
				}
				err = txInner.Commit()
				if err != nil {
					return
				}
			}

		}

		initialValuesToQueue.Do(func() {
			for {
				fmt.Println("\n***********************************************************")
				fmt.Println("Building Query..", len(d.emailQueue))
				fmt.Println("***********************************************************")

				// Regular monitoring every 10 seconds
				//d.mu.Lock()
				if len(d.emailQueue) < 1000 {

					qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
					conditions := map[string]interface{}{
						"status_name": "undownloaded",
					}

					existingIDs := make([]int, len(d.emailQueue))
					for i, email := range d.emailQueue {
						existingIDs[i] = email.ID
					}

					query, values, err := qb.BuildSelectQuery("mail.tracker_table", []string{"email_id"}, conditions, "email_id DESC", -1, nil)
					if err != nil {
						fmt.Println("Error building query:", err)
						d.mu.Unlock()
					}

					db := DB.DB

					tx, err := db.Begin()
					if err != nil {
						continue
					}

					rows, err := tx.Query(query, values...)
					if err != nil {
						fmt.Println("Error executing query in monitor:", err)
						err := tx.Rollback()
						if err != nil {
							return
						}
						d.mu.Unlock()
						continue
					}
					defer func(rows *sql.Rows) {
						err := rows.Close()
						if err != nil {
							err := tx.Rollback()
							if err != nil {
								return
							}
						}
					}(rows)

					count := 0

					fmt.Println("Adding Initial Mails to Queue")

					for rows.Next() {
						if count < 1000 {
							var emailId int
							if err := rows.Scan(&emailId); err != nil {
								fmt.Println("Error scanning row:", err)
								continue
							}
							inQueue := false
							for _, email := range d.emailQueue {
								if email.ID == emailId {
									inQueue = true
									break
								}
							}

							// If it's not in the queue, add it
							if !inQueue {
								heap.Push(&d.emailQueue, &Email{
									ID:       emailId,
									Priority: emailId, // Priority based on ID
								})
								count++

							}
						} else {
							break
						}

					}

					err = tx.Commit()
					if err != nil {
						continue
					}
					fmt.Println("Done Adding Initial Mails to Queue")
				}
				d.mu.Unlock()
				break
			}

		})

		go d.monitorDatabaseForEmails()

		handler := &imapB.IdleHandler{
			OnExists: func(event imapB.ExistsEvent) {
				d.newMails.Store(event.MessageIndex, event.MessageIndex)
			},
			OnExpunge: func(event imapB.ExpungeEvent) {
				fmt.Printf("Message expunged at index: %d\n", event.MessageIndex)
			},
			OnFetch: func(event imapB.FetchEvent) {
				fmt.Printf("Message fetched: Index=%d, UID=%d, Flags=%v\n", event.MessageIndex, event.UID, event.Flags)
			},
		}

		err = im.StartIdle(handler)
		if err != nil {
			return
		}

		time.Sleep(10 * time.Minute)

	}
}

func (d *EmailDownloader) Start() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	// Initialize the priority queue
	heap.Init(&d.emailQueue)
	go d.checkForNewEmails()
	go d.NewMails()

	go func() {
		for {
			d.MailBox(1)
		}
	}()

	go func() {
		for {
			d.MailBox(2)
		}
	}()

	go func() {
		for {
			d.MailBox(3)
		}
	}()
	go func() {
		for {
			d.MailBox(4)
		}
	}()

	go func() {
		for {
			d.MailBox(5)
		}
	}()

	go func() {
		for {
			d.MailBox(6)
		}
	}()
	go func() {
		for {
			d.MailBox(7)
		}
	}()

	go func() {
		for {
			d.MailBox(8)
		}
	}()
	go func() {
		for {
			d.MailBox(9)
		}
	}()

	go func() {
		for {
			d.MailBox(10)
		}
	}()
	for {

	}

}

func (d *EmailDownloader) im() *imapBrian.Dialer {
	var im *imapBrian.Dialer

	for {
		token, err := fetchNewToken(d.DownloadPayload.TokenCredential)
		if err != nil {
			fmt.Println("Error generating access token, retrying...")
			continue
		}
		im, err = imapBrian.NewWithOAuth2Copy(d.DownloadPayload.Credentials.Email, token, d.DownloadPayload.ServerConfig.Host, d.DownloadPayload.ServerConfig.Port)
		if err != nil {
			fmt.Println("Error connecting to IMAP: ", err.Error())
			continue
		}

		break
	}
	return im
}

func (d *EmailDownloader) MailBox(id int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	d.mu.Lock()
	if d.emailQueue.Len() > 0 {
		im := d.im()
		defer func(im *imapBrian.Dialer) {
			err := im.Close()
			if err != nil {

			}
		}(im)

		err := im.SelectFolder("INBOX")
		//	check(err)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Get the highest priority email
		var uids []int

		for i := 1; i <= 5; i++ {
			email := heap.Pop(&d.emailQueue).(*Email)
			uids = append(uids, email.ID)
			d.downloadingEmails.Store(email.ID, true)
		}

		d.mu.Unlock()

		fmt.Println("***********************************************************")
		fmt.Println("Pulling Email from server IDS::", uids, " <- ", id)
		fmt.Println("***********************************************************\n")
		emails, _ := im.GetEmails(uids...)

		if len(emails) > 0 {
			fmt.Println("***********************************************************")
			fmt.Println("Done Pulling Now saving to DB")
			fmt.Println("***********************************************************\n")
			for _, id := range uids {
				//emailIDStr := fmt.Sprintf("%d", email.ID)
				attachments := []AttachmentInfo{}

				emailStruct, exists := emails[id]

				toStr := ""
				ccStr := ""
				//inReplyTo := ""
				//replyToStr1 := ""
				replyToStr := ""
				bccStr := ""
				fromStr := ""
				subject := ""
				messageID := ""
				htmlBody := ""
				textBody := ""
				var date time.Time

				var emailFields map[string]string

				if exists {

					toStr = EmailAddressesToStr(emailStruct.To)
					ccStr = EmailAddressesToStr(emailStruct.CC)
					bccStr = EmailAddressesToStr(emailStruct.BCC)
					fromStr = EmailAddressesToStr(emailStruct.From)
					//replyToStr = EmailAddressesToStr(emailStruct.ReplyTo)
					replyToStr = emailStruct.InReplyTo
					// inReplyTo = emailStruct.InReplyTo
					date = emailStruct.Received
					subject = emailStruct.Subject
					messageID = emailStruct.MessageID
					htmlBody = emailStruct.HTML
					textBody = emailStruct.Text

					//fmt.Println("Inreply to ", replyToStr, " Reply to ", replyToStr1)

					for _, attachment := range emailStruct.Attachments {

						attachments = append(attachments, AttachmentInfo{
							Filename: attachment.Name,
							MimeType: attachment.MimeType,
						})
						err := saveAttachment(id, attachment.Name, bytes.NewReader(attachment.Content), d.DownloadPayload.FileConfig.Filename)

						if err != nil {
							fmt.Println("Error saving attachment:", err)
							continue
						}

					}

					attachmentsJSON1, err := json.Marshal(attachments)
					if err != nil {
						time.Sleep(500 * time.Millisecond)
						return
					}

					var attachment string

					if strings.Trim(string(attachmentsJSON1), "[]") != "" {
						attachment = "yes"
					} else {
						attachment = ""
					}

					emailFields = map[string]string{
						"MESSAGEID":   messageID,
						"MID":         strconv.Itoa(id),
						"FROM":        fromStr,
						"TO":          toStr,
						"CC":          ccStr,
						"SENDERNAME":  fromStr,
						"BCC":         bccStr,
						"SUBJECT":     subject,
						"DATE":        date.Format("2006-01-02 15:04:05"),
						"REPLYTO":     replyToStr,
						"HTMLBODY":    textBody,
						"TEXTBODY":    htmlBody,
						"ATTACHMENTS": attachment,
					}

				} else {
					return
				}

				attachmentsJSON, err := json.Marshal(attachments)
				if err != nil {
					time.Sleep(500 * time.Millisecond)
					return
				}

				var customData sync.Map

				d.DownloadPayload.CustomColumns.Range(func(key, value interface{}) bool {

					// Safely assert value to string to avoid a panic
					valStr, ok := value.(string)
					if !ok {
						fmt.Println("Value is not a string, skipping")
						return true // Continue to next entry if value is not a string
					}

					// Evaluate the custom field
					val, err := evaluateCustomField(valStr, emailFields)
					if err != nil {
						fmt.Println("Error evaluating custom field, setting value to empty", err)
						val = ""
					}

					//	fmt.Printf("Key: %v, Value: %v\n", key, val)

					// Store the result in customData map
					customData.Store(key, val)

					return true // Continue iterating through all elements
				})

				data := &customData

				if d.DownloadPayload.EmailFields.To != "" {
					data.Store(d.DownloadPayload.EmailFields.To, toStr)
				}

				if d.DownloadPayload.EmailFields.SenderName != "" {
					data.Store(d.DownloadPayload.EmailFields.SenderName, fromStr)

				}

				if d.DownloadPayload.EmailFields.MID != "" {
					data.Store(d.DownloadPayload.EmailFields.MID, id)
				}

				if d.DownloadPayload.EmailFields.From != "" {
					data.Store(d.DownloadPayload.EmailFields.From, fromStr)
				}

				if d.DownloadPayload.EmailFields.Bcc != "" {
					data.Store(d.DownloadPayload.EmailFields.Bcc, bccStr)
				}

				if d.DownloadPayload.EmailFields.Cc != "" {
					data.Store(d.DownloadPayload.EmailFields.Cc, ccStr)
				}

				if d.DownloadPayload.EmailFields.ReplyTo != "" {
					data.Store(d.DownloadPayload.EmailFields.ReplyTo, replyToStr)
				}

				if d.DownloadPayload.EmailFields.Attachments != "" {
					data.Store(d.DownloadPayload.EmailFields.Attachments, string(attachmentsJSON))
				}

				if d.DownloadPayload.EmailFields.Subject != "" {
					data.Store(d.DownloadPayload.EmailFields.Subject, subject)
				}

				if d.DownloadPayload.EmailFields.HtmlBody != "" {
					data.Store(d.DownloadPayload.EmailFields.HtmlBody, htmlBody)
				}

				if d.DownloadPayload.EmailFields.TextBody != "" {
					data.Store(d.DownloadPayload.EmailFields.TextBody, textBody)
				}

				if d.DownloadPayload.EmailFields.MessageID != "" {
					data.Store(d.DownloadPayload.EmailFields.MessageID, messageID)
				}

				if d.DownloadPayload.EmailFields.Date != "" {
					data.Store(d.DownloadPayload.EmailFields.Date, date.Format("2006-01-02 15:04:05"))
				}

				db := DB.DB

				//stats := db.Stats()
				//
				//// Print the connection stats
				//fmt.Println("Connection Stats:")
				//fmt.Printf("Max Open Connections: %d\n", stats.MaxOpenConnections)
				//fmt.Printf("Open Connections: %d\n", stats.OpenConnections)
				//fmt.Printf("Idle Connections: %d\n", stats.Idle)
				//fmt.Printf("In Use Connections: %d\n", stats.InUse)
				//fmt.Printf("Wait Count: %d\n", stats.WaitCount)
				//fmt.Printf("Wait Duration: %s\n", stats.WaitDuration)
				//fmt.Printf("Max Idle Closed: %d\n", stats.MaxIdleClosed)
				//fmt.Printf("Max Lifetime Closed: %d\n", stats.MaxLifetimeClosed)

				tx, err := db.Begin()
				if err != nil {
					return
				}

				defer func(tx *sql.Tx) {
					err := tx.Rollback()
					if err != nil {

					}
				}(tx)

				qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
				query, values, err := qb.BuildInsertQuery(d.DownloadPayload.DBConfig.Table, data)
				if err != nil {
					fmt.Println("Error building query:", err)
					time.Sleep(500 * time.Millisecond)
					return
				}

				//query2, values2, err := qb.BuildBatchInsertQuery(d.DownloadPayload.DBConfig.Table, data)

				// Execute the query
				_, err = tx.Exec(query, values...)

				if err != nil {
					fmt.Println("Error Inserting new mail", id)

					now := time.Now()
					formattedTime := now.Format("2006-01-02 15:04:05")
					updates := map[string]interface{}{
						"status_name":        "error",
						"status_description": err.Error(),
						"status_date":        formattedTime,
					}

					conditions := map[string]interface{}{
						"email_id": id,
					}

					query, values, err := qb.BuildUpdateQuery("mail.tracker_table", updates, conditions)

					tx2, err := db.Begin()
					if err != nil {
						return
					}

					defer func(tx2 *sql.Tx) {
						err := tx2.Rollback()
						if err != nil {

						}
					}(tx2)

					_, err = tx2.Exec(query, values...)
					if err != nil {
						fmt.Println("Error updating status query:", err.Error())
						err := tx2.Rollback()
						if err != nil {
							return
						}
						continue
					} else {
						err := tx2.Commit()
						if err != nil {
							return
						}
					}
					err = tx.Rollback()
					if err != nil {
						return
					}
					d.downloadingEmails.Delete(id)
					time.Sleep(500 * time.Millisecond)
					return
				} else {
					now := time.Now()
					formattedTime := now.Format("2006-01-02 15:04:05")
					updates := map[string]interface{}{
						"status_name":        "downloaded",
						"status_description": "",
						"status_date":        formattedTime,
					}

					conditions := map[string]interface{}{
						"email_id": id,
					}

					query, values, err := qb.BuildUpdateQuery("mail.tracker_table", updates, conditions)

					tx3, err := db.Begin()
					if err != nil {
						return
					}

					defer func(tx3 *sql.Tx) {
						err := tx3.Rollback()
						if err != nil {

						}
					}(tx3)

					_, err = tx3.Exec(query, values...)
					if err != nil {
						fmt.Println("Error updating status query success:", err)
						err := tx3.Rollback()
						if err != nil {
							return
						}
						continue
					}
					err = tx3.Commit()
					if err != nil {
						return
					}

					err = tx.Commit()
					if err != nil {
						return
					}
					d.downloadingEmails.Delete(id)
				}
			}

		}
		fmt.Println("***********************************************************")
		fmt.Println("Done Email Saved")
		fmt.Println("***********************************************************\n")
	} else {
		return
	}

	d.mu.Lock()
	d.mu.Unlock()

	time.Sleep(500 * time.Millisecond)

}

func (d *EmailDownloader) NewMails() {
	for {
		isEmpty := true

		d.newMails.Range(func(key, value interface{}) bool {
			isEmpty = false
			return false
		})

		if isEmpty {
			time.Sleep(5 * time.Second)
			continue
		}
		now := time.Now()
		columns := []string{"email_id", "priority", "status_name", "status_date", "date_created"}
		formattedTime := now.Format("2006-01-02 15:04:05")
		var rows [][]interface{}
		qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
		query, values, err := qb.BuildCountQuery("mail.tracker_table", nil)
		if err != nil {
			fmt.Println("Error building count query...")
			continue
		}

		db := DB.DB
		txInner, err := db.Begin()
		if err != nil {
			continue
		}

		d.newMails.Range(func(key, value interface{}) bool {
			emailIDStr := fmt.Sprintf("%d", key)
			row := []interface{}{emailIDStr, emailIDStr, "undownloaded", formattedTime, formattedTime}
			rows = append(rows, row)
			return true
		})

		query, values, err = qb.BuildInsertBatchQuery("mail.tracker_table", columns, rows)
		if err != nil {
			fmt.Println("Error building query:", err)
			return
		}

		// Execute the query
		_, err = txInner.Exec(query, values...)
		if err != nil {
			fmt.Println("Error executing query in check mail undowloaded:", err)
			return
		}

		err = txInner.Commit()
		if err != nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
}

func (d *EmailDownloader) monitorDatabaseForEmails() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			log.Printf("Stack trace: \n%s", string(debug.Stack()))
		}
	}()

	// Ticker for 10-second monitoring intervals
	monitorTicker := time.NewTicker(2 * time.Second)
	defer monitorTicker.Stop()

	//checkNew := time.NewTicker(5 * time.Second)
	//defer checkNew.Stop()

	for {

		select {
		case <-monitorTicker.C:
			// Regular monitoring every 10 seconds
			d.mu.Lock()
			if len(d.emailQueue) < 1000 {

				qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
				conditions := map[string]interface{}{
					"status_name": "undownloaded",
				}

				existingIDs := make([]int, len(d.emailQueue))
				for i, email := range d.emailQueue {
					existingIDs[i] = email.ID
				}

				query, values, err := qb.BuildSelectQuery("mail.tracker_table", []string{"email_id"}, conditions, "email_id DESC", -1, nil)
				if err != nil {
					fmt.Println("Error building query:", err)
					if err != nil {
						return
					}
					d.mu.Unlock()
					continue
				}

				db := DB.DB
				tx, err := db.Begin()
				if err != nil {
					return
				}
				rows, err := tx.Query(query, values...)
				if err != nil {
					fmt.Println("Error executing query in monitor:", err)
					if err != nil {
						return
					}
					d.mu.Unlock()
					err := tx.Rollback()
					if err != nil {
						return
					}
					continue
				}
				defer rows.Close()
				count := 0

				for rows.Next() {
					if count < 1000-len(d.emailQueue) {
						var emailId int
						if err := rows.Scan(&emailId); err != nil {
							fmt.Println("Error scanning row:", err)
							if err != nil {
								return
							}
							err := rows.Close()
							if err != nil {
								return
							}
							continue
						}

						// Check if the email is already in the downloading state
						if _, exists := d.downloadingEmails.Load(emailId); exists {
							continue
						}

						inQueue := false
						for _, email := range d.emailQueue {
							if email.ID == emailId {
								inQueue = true
								break
							}
						}

						// If it's not in the queue, add it
						if !inQueue {
							heap.Push(&d.emailQueue, &Email{
								ID:       emailId,
								Priority: emailId, // Priority based on ID
							})
							count++
						}

					} else {
						break
					}
				}

				// Commit transaction only after processing the rows
				if err := tx.Commit(); err != nil {
					fmt.Println("Error committing transaction:", err)
					d.mu.Unlock()
					return
				}

			}
			d.mu.Unlock()
			//case <-checkNew.C:
			//	db := DB.DB
			//	tx, err := db.Begin()
			//
			//	if err != nil {
			//		fmt.Println("Error Stating Commit..")
			//		continue
			//	}
			//
			//	qb := QueryBuilder.NewQueryBuilder(d.DownloadPayload.DBConfig.DBType)
			//	query, values, err := qb.BuildCountQuery("mail.tracker_table", nil)
			//	if err != nil {
			//		fmt.Println("Error building count query...")
			//		continue
			//	}
			//
			//	var count int
			//	err = db.QueryRow(query, values...).Scan(&count)
			//	if err != nil {
			//		fmt.Println("Error running select query...")
			//		continue
			//	}
			//
			//	err = tx.Commit()
			//	if err != nil {
			//		return
			//	}
			//
			//	im := d.im()
			//	defer im.Close()
			//
			//	err = im.SelectFolder("INBOX")
			//	//	check(err)
			//
			//	seqNums, err := im.GetUIDs("ALL")
			//	if err != nil {
			//		fmt.Println("Error searching emails:", err)
			//		//continue
			//	}
			//
			//	if len(seqNums) > count {
			//
			//		fmt.Println("New Message")
			//
			//		query, values, err := qb.BuildSelectQuery("mail.tracker_table", []string{"email_id"}, nil, "email_id DESC", -1, nil)
			//		if err != nil {
			//			fmt.Println("Error building query:", err)
			//			if err != nil {
			//				return
			//			}
			//		}
			//
			//		tx, err := db.Begin()
			//		if err != nil {
			//			return
			//		}
			//		rows, err := tx.Query(query, values...)
			//		if err != nil {
			//			fmt.Println("Error executing query in monitor:", err)
			//			if err != nil {
			//				return
			//			}
			//			err := tx.Rollback()
			//			if err != nil {
			//				return
			//			}
			//		}
			//		defer rows.Close()
			//
			//		existingEmailIDs := make(map[int]struct{})
			//		for rows.Next() {
			//			var emailId int
			//			if err := rows.Scan(&emailId); err != nil {
			//				fmt.Println("Error scanning row:", err)
			//				_ = rows.Close()
			//				return
			//			}
			//			existingEmailIDs[emailId] = struct{}{}
			//		}
			//
			//		for _, seqNum := range seqNums {
			//			if _, exists := existingEmailIDs[seqNum]; !exists {
			//				// Prepare insert query
			//
			//				now := time.Now()
			//				formattedTime := now.Format("2006-01-02 15:04:05")
			//				columns := []string{"email_id", "priority", "status_name", "status_date", "date_created"}
			//
			//				mailIDStr := fmt.Sprintf("%d", seqNum)
			//				row := []interface{}{mailIDStr, mailIDStr, "undownloaded", formattedTime, formattedTime}
			//
			//				var rows [][]interface{}
			//				rows = append(rows, row)
			//				query, values, err := qb.BuildInsertBatchQuery("mail.tracker_table", columns, rows)
			//				if err != nil {
			//					fmt.Println("Error building query:", err)
			//					_ = tx.Rollback()
			//					return
			//				}
			//
			//				// Execute the query
			//				_, err = tx.Exec(query, values...)
			//				if err != nil {
			//					fmt.Println("Error executing query in check mail undownloaded:", err)
			//					_ = tx.Rollback()
			//					continue
			//				}
			//			}
			//		}
			//
			//		// Commit transaction only after processing the rows
			//		if err := tx.Commit(); err != nil {
			//			fmt.Println("Error committing transaction:", err)
			//			return
			//		}
			//	}
			//
		}
	}
}
