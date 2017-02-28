package io.dathena.services

import scala.io.Source._

import java.sql.{Connection, DriverManager, PreparedStatement, ResultSet}
import java.util.Properties

import org.json.{JSONArray, JSONObject}

import io.dathena.tools.HbaseReadTest

class AnomalyAccessRight {

  // FIXME: Read from Dathena.conf
  val hostnames: List[String] = fromFile("hostnames").getLines.toList
  val hostname: String = hostnames(3).split('=')(1).trim
  var updatevalue4: UpdateData = new UpdateData()

  def getADGroups(user: String): String = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"memberOf_1\" from \"Dathena:USERS\" where \"key\" = ?"
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, user)
    val rst: ResultSet = query.executeQuery()
    rst.next()
    val group: String = rst.getString(1)
    connection.close()
    return group
  }

  def getUserFromGuid(id: String): String = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"key\" from \"Dathena:USERS\" where \"objectGUID\" = ?"
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, id)
    val rst: ResultSet = query.executeQuery()
    rst.next()
    val user: String = rst.getString(1)
    connection.close()
    return user
  }

  //API-AD Group
  def getAccessRightFirstTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = """
      SELECT
        TO_NUMBER("Accuracy") * 100 AS "User Access Right Accuracy",
        "Confidentiality" AS "Confidentiality at Risk",
        TO_NUMBER("FoldersAmount") AS "Folder at Risk",
        TO_NUMBER("GroupAmount") AS "Active Directory Group at Risk",
        TO_NUMBER("UsersAmount") AS "User Anomaly"
      FROM "Dathena:AccessRightAnomaly"
      WHERE
        "key" LIKE 'access_anomaly_%'
      """
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
  //*****************END******************

  def getAccessRightSecondTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"TotalUserAnomaly\") as \"Total Anomaly\",TO_NUMBER(\"TotalDocumentsAtRisk\") as \"Document at Risk\",TO_NUMBER(\"TotalGroupAnomaly\") as \"Total Active Directory Group at Risk\"  from \"Dathena:AccessRightAnomaly\" where \"key\" = 'access_anomaly'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "ClientDataSecond")
    connection.close()
    return response
  }

  //API-3,4
  def getAccessRightHighRiskUsers(filter: String, limit: Int = 100): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql =
        s"""
          SELECT
            "owner" AS "Windows User Account",
            TO_NUMBER("FilesAmount") AS "Document at Risk",
            "Confidentiality",
            TO_NUMBER("FoldersAmount") AS "Folder at Risk",
            "ReviewStatus" AS "Review Status",
            "SecurityInFault" AS "Security in Fault"
          FROM "Dathena:AccessRightAnomaly"
          WHERE
            "key" LIKE 'summary_access_anomaly_%'
            AND "ReviewStatus" LIKE ?
          LIMIT $limit
        """
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = s"""
        SELECT
          "owner" AS "Windows User Account",
          TO_NUMBER("FilesAmount") AS "Document at Risk",
          "Confidentiality",
          TO_NUMBER("FoldersAmount") AS "Folder at Risk",
          "ReviewStatus" AS "Review Status",
          "SecurityInFault" AS "Security in Fault"
        FROM "Dathena:AccessRightAnomaly"
        WHERE
          "key" LIKE 'summary_access_anomaly_%'
        LIMIT $limit
        """
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
  //*****************END******************

  //Converts ResultSet object to JSON
  def convertResultSetIntoJSON(resultSet: ResultSet, customColumn: String): JSONArray = {
    val jsonArray: JSONArray = new JSONArray()
    val timeStamps: List[String] = new HbaseReadTest().getTimeStamps("timestamp", "Dathena:AccessRightAnomaly", "access_anomaly", "Anomaly", "TotalUserAnomaly")
    val totalAnomaly: List[String] = new HbaseReadTest().getTimeStamps("TotalUserAnomaly", "Dathena:AccessRightAnomaly", "access_anomaly", "Anomaly", "TotalUserAnomaly")
    while (resultSet.next())
    {
      val total_rows: Int = resultSet.getMetaData.getColumnCount
      val obj: JSONObject = new JSONObject()
      for (i <- 0 until total_rows)
      {
        var columnName: String = resultSet.getMetaData.getColumnLabel(i + 1)
        //.toLowerCase()
        var columnValue: AnyRef = resultSet.getObject(i + 1)
        if (obj.has(columnName))
        {
          columnName += "1"
        }

        if (columnName == "Windows User Account" && customColumn == "")
        {
          obj.put("id", getGUID(columnValue.toString))
        }

        if (customColumn == "ClientDataSecond")
        {
          if (columnName == "Total Anomaly")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Windows User Account")
            println(timeStamps.size)
            if (timeStamps.size >= 2)
            {
              if (getAccessRightPreviousValues(timeStamps(1).toString, "TotalUserAnomaly").toInt > Integer.parseInt(columnValue.toString))
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1

            println(timeStamps.size)
            if (timeStamps.nonEmpty)
            {
              val jsonValue: JSONArray = new JSONArray()
              var occurence: Int = 1
              for (i <- totalAnomaly.reverse)
              {
                println(i)
                val tempValue: Long = Math.round(i.toFloat)
                val obj2: JSONObject = new JSONObject()
                obj2.put("users", tempValue)
                obj2.put("occurence", occurence)
                occurence += 1
                var occurence_type: String = "medium"
                if (tempValue < 33)
                {
                  occurence_type = "low"
                }
                else if (tempValue >= 66)
                {
                  occurence_type = "high"
                }
                obj2.put("type", occurence_type)
                jsonValue.put(obj2)
              }
              obj.put("Access Right Anomaly Trend", jsonValue)
            }
          }
          
          if (columnName == "Document at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Documents")
            if (timeStamps.size >= 2)
            {
              if (getAccessRightPreviousValues(timeStamps(1).toString, "TotalDocumentsAtRisk").toInt > Integer.parseInt(columnValue.toString))
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }
          if (columnName == "Total Active Directory Group at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Active Directory Group")
            if (timeStamps.size >= 2)
            {
              if (getAccessRightPreviousValues(timeStamps(1).toString, "TotalGroupAnomaly").toInt > Integer.parseInt(columnValue.toString))
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }
        }

        obj.put(columnName, columnValue)
      }
      if (obj.length() != 0)
      {
        jsonArray.put(obj)
      }
    }
    return jsonArray
  }

  def getGUID(user: String): String = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"objectGUID\" from \"Dathena:USERS\" where \"key\" = ?"
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, user)
    val rst: ResultSet = query.executeQuery()
    var guid: String = ""
    while (rst.next())
    {
      guid = rst.getString(1)
    }
    connection.close()
    return guid
  }

  def getAccessRightPreviousValues(ts: String, column: String): Long = {
    val connection: Connection = Common.getConnection(ts)
    //println(ts)
    val sql: String = "select TO_NUMBER(\"" + column + "\") from \"Dathena:AccessRightAnomaly\" where \"key\" = 'access_anomaly'"
    println(sql)
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    var value: Long = 0
    if (rst.next())
    {
      value = rst.getLong(1)
    }
    connection.close()
    return value
  }
}
