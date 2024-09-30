package QueryBuilder

import (
	"awesomeProject/DB"
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

type QueryBuilder struct {
	DBType string
}

type QueryBuilder1 struct {
	DB     *sql.DB
	DBType string
}

func NewQueryBuilder1(db *sql.DB, dbType string) *QueryBuilder1 {
	return &QueryBuilder1{
		DB:     db,
		DBType: dbType,
	}
}

func NewQueryBuilder(dbType string) *QueryBuilder {
	return &QueryBuilder{
		DBType: dbType,
	}
}
func syncMapToMap(sm *sync.Map) map[string]interface{} {
	result := make(map[string]interface{})
	sm.Range(func(key, value interface{}) bool {
		strKey, okKey := key.(string)
		if !okKey {
			return false
		}
		result[strKey] = value
		return true
	})
	return result
}

func syncMapToMap2(sm *sync.Map) map[string]interface{} {
	result := make(map[string]interface{})
	sm.Range(func(key, value interface{}) bool {
		strKey, okKey := key.(string)
		if !okKey {
			return false
		}

		// Check if the value is another sync.Map
		if innerMap, okInner := value.(*sync.Map); okInner {
			result[strKey] = syncMapToMap(innerMap) // Recursively convert inner map
		} else {
			result[strKey] = value // Store the value directly
		}
		return true
	})
	return result
}
func (qb *QueryBuilder) BuildInsertQuery(tableName string, data *sync.Map) (string, []interface{}, error) {
	dataMap := syncMapToMap(data)

	columns := make([]string, 0, len(dataMap))
	placeholders := make([]string, 0, len(dataMap))
	values := make([]interface{}, 0, len(dataMap))

	for col, val := range dataMap {
		columns = append(columns, col)
		placeholders = append(placeholders, qb.getPlaceholder(len(placeholders)+1))
		values = append(values, val)
	}

	if qb.DBType == "postgres" {
		tableName = "mbanking_logs." + tableName
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	return query, values, nil
}

//func (qb *QueryBuilder) BuildBatchInsertQuery(tableName string, dataList *sync.Map) (string, []interface{}, error) {
//	dataMap := syncMapToMap2(dataList)
//
//	columns := make([]string, 0, len(dataMap))
//	placeholders := make([]string, 0, len(dataMap))
//	values := make([]interface{}, 0, len(dataMap))
//
//	for _, outerValue := range dataMap {
//		// Check if the value is a nested map
//		placeholderSet := make([]string, len(columns))
//		if data, ok := outerValue.(map[string]interface{}); ok {
//			// Loop through the inner map
//			for col, val := range data {
//				columns = append(columns, col)
//				placeholderSet[i] = qb.getPlaceholder(len(values) + 1)
//				values = append(values, data[col])
//			}
//		}
//	}
//
//	for col, val := range dataMap {
//		columns = append(columns, col)
//		placeholders = append(placeholders, qb.getPlaceholder(len(placeholders)+1))
//		values = append(values, val)
//	}
//
//	for _, data := range dataMap {
//		placeholderSet := make([]string, len(columns))
//
//		for i, col := range data {
//			placeholderSet[i] = qb.getPlaceholder(len(values) + i + 1)
//			values = append(values, data[col])
//		}
//		placeholders = append(placeholders, fmt.Sprintf("(%s)", strings.Join(placeholderSet, ", ")))
//	}
//
//	if qb.DBType == "postgres" {
//		tableName = "mbanking_logs." + tableName
//	}
//
//	query := fmt.Sprintf(
//		"INSERT INTO %s (%s) VALUES (%s)",
//		tableName,
//		strings.Join(columns, ", "),
//		strings.Join(placeholders, ", "),
//	)
//
//	return query, values, nil
//
//}

func (qb *QueryBuilder) getPlaceholder(index int) string {
	switch qb.DBType {
	case "postgres":
		return fmt.Sprintf("$%d", index)
	case "mysql":
		return "?"
	default:
		return "?"
	}
}
func (qb *QueryBuilder1) GetColumnNames(tableName string) ([]string, error) {
	var query string
	var rows *sql.Rows
	var err error

	switch qb.DBType {
	case "postgres":
		query = `
			SELECT column_name
			FROM information_schema.columns
			WHERE table_name = $1
			ORDER BY ordinal_position`
		rows, err = DB.DB.Query(query, tableName)
	case "mysql":
		query = `
			SELECT column_name
			FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = ?`
		rows, err = DB.DB.Query(query, tableName)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", qb.DBType)
	}

	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	var columnNames []string
	for rows.Next() {
		var columnName string
		if err := rows.Scan(&columnName); err != nil {
			return nil, err
		}
		columnNames = append(columnNames, columnName)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return columnNames, nil
}
func (qb *QueryBuilder) BuildSelectQuery(
	tableName string,
	columns []string,
	conditions map[string]interface{},
	orderBy string,
	limit int,
	excludedIDs []int,
) (string, []interface{}, error) {
	var query strings.Builder
	var values []interface{}

	// If no columns are specified, select all columns
	if len(columns) == 0 {
		query.WriteString(fmt.Sprintf("SELECT * FROM %s", tableName))
	} else {
		query.WriteString(fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), tableName))
	}

	// Add conditions if there are any
	if len(conditions) > 0 {
		conditionClauses := make([]string, 0, len(conditions))
		i := 1
		for col, val := range conditions {
			conditionClauses = append(conditionClauses, fmt.Sprintf("%s = %s", col, qb.getPlaceholder(i)))
			values = append(values, val)
			i++
		}
		query.WriteString(" WHERE " + strings.Join(conditionClauses, " AND "))
	}

	// Add exclusion of specific IDs
	if len(excludedIDs) > 0 {
		placeholders := make([]string, len(excludedIDs))
		for i := range excludedIDs {
			placeholders[i] = qb.getPlaceholder(i + len(values) + 1)
			values = append(values, excludedIDs[i])
		}
		query.WriteString(fmt.Sprintf(" AND email_id NOT IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Add ORDER BY clause if specified
	if orderBy != "" {
		query.WriteString(fmt.Sprintf(" ORDER BY %s", orderBy))
	}

	// Add LIMIT clause if specified and greater than 0
	if limit > 0 {
		query.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	}

	return query.String(), values, nil
}

func (qb *QueryBuilder) BuildCountQuery(tableName string, conditions map[string]interface{}) (string, []interface{}, error) {
	var query strings.Builder
	var values []interface{}

	query.WriteString(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName))

	// Add conditions if there are any
	if len(conditions) > 0 {
		conditionClauses := make([]string, 0, len(conditions))
		i := 1
		for col, val := range conditions {
			conditionClauses = append(conditionClauses, fmt.Sprintf("%s = %s", col, qb.getPlaceholder(i)))
			values = append(values, val)
			i++
		}
		query.WriteString(" WHERE " + strings.Join(conditionClauses, " AND "))
	}

	return query.String(), values, nil
}
func (qb *QueryBuilder) BuildInsertBatchQuery(tableName string, columns []string, rows [][]interface{}) (string, []interface{}, error) {
	if len(columns) == 0 || len(rows) == 0 {
		return "", nil, fmt.Errorf("columns and rows must not be empty")
	}

	var query strings.Builder
	var values []interface{}
	numColumns := len(columns)

	// Construct the beginning of the query
	query.WriteString(fmt.Sprintf("INSERT INTO %s (%s) VALUES ", tableName, strings.Join(columns, ", ")))

	// Construct the placeholders for each row
	placeholders := make([]string, 0, len(rows))
	for i, row := range rows {
		if len(row) != numColumns {
			return "", nil, fmt.Errorf("row %d does not have the correct number of columns", i)
		}

		rowPlaceholders := make([]string, numColumns)
		for j := 0; j < numColumns; j++ {
			rowPlaceholders[j] = qb.getPlaceholder(len(values) + 1)
			values = append(values, row[j])
		}
		placeholders = append(placeholders, fmt.Sprintf("(%s)", strings.Join(rowPlaceholders, ", ")))
	}

	// Join the rows' placeholders and append them to the query
	query.WriteString(strings.Join(placeholders, ", "))

	return query.String(), values, nil
}
func (qb *QueryBuilder) BuildUpdateQuery(
	tableName string,
	updates map[string]interface{},
	conditions map[string]interface{},
) (string, []interface{}, error) {
	var query strings.Builder
	var values []interface{}

	// Construct the SET clause
	setClauses := make([]string, 0, len(updates))
	for col, val := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = %s", col, qb.getPlaceholder(len(values)+1)))
		values = append(values, val)
	}

	if len(setClauses) == 0 {
		return "", nil, fmt.Errorf("no columns to update")
	}

	query.WriteString(fmt.Sprintf("UPDATE %s SET %s", tableName, strings.Join(setClauses, ", ")))

	// Add conditions if there are any
	if len(conditions) > 0 {
		conditionClauses := make([]string, 0, len(conditions))
		i := len(values) + 1
		for col, val := range conditions {
			conditionClauses = append(conditionClauses, fmt.Sprintf("%s = %s", col, qb.getPlaceholder(i)))
			values = append(values, val)
			i++
		}
		query.WriteString(" WHERE " + strings.Join(conditionClauses, " AND "))
	}

	return query.String(), values, nil
}
