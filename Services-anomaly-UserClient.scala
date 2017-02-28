package io.dathena.services

import scala.io.Source._

import java.sql.{Connection, DriverManager, PreparedStatement, ResultSet}
import java.util.Properties

import org.json.{JSONArray, JSONObject}

import io.dathena.tools.HbaseReadTest

class AnomalyUserClient {

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
  def getUserClientFirstTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = """
      SELECT
        TO_NUMBER("Accuracy") * 100 AS "User Access Right Accuracy",
        "Confidentiality" AS "Confidentiality at Risk",
        TO_NUMBER("FolderAtRisk") AS "Folder at Risk",
        TO_NUMBER("ActiveDirectoryAtRisk") AS "Active Directory at Risk",
        TO_NUMBER("UserAnomaly") AS "User with Anomaly"
      FROM "Dathena:UserClientAnomaly"
      WHERE
        "key" LIKE 'user_client_anomaly_%'
      """
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
  //*****************END******************

  def getUserClientSecondTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"TotalActiveDirectoryAtRisk\") as \"Security Settings at Risk\",TO_NUMBER(\"TotalAnomaly\") as \"Total Anomaly\",TO_NUMBER(\"TotalDocumentsAtRisk\") as \"Client Data at Risk\"  from \"Dathena:UserClientAnomaly\" where \"key\" = 'user_client_anomaly'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "ClientDataSecond")
    connection.close()
    return response
  }

  //API-3,4
  def getUserClientHighRiskUsers(filter: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = "select \"owner\" as \"Windows User Account\",TO_NUMBER(\"FilesAtRisk\") as \"Document at Risk\",\"Confidentiality\",TO_NUMBER(\"FolderAtRisk\") as \"Folder at Risk\",\"ReviewStatus\" as \"Review Status\",\"SecurityInFault\" as \"Security in Fault\" from \"Dathena:UserClientAnomaly\" where \"key\" like 'summary_user_client_anomaly_%' and \"ReviewStatus\" like ?"
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = """SELECT "owner" AS "Windows User Account", TO_NUMBER("FilesAtRisk") AS "Document at Risk", "Confidentiality", TO_NUMBER("FolderAtRisk") AS "Folder at Risk", "ReviewStatus" AS "Review Status", "SecurityInFault" AS "Security in Fault" FROM "Dathena:UserClientAnomaly" WHERE "key" LIKE 'summary_user_client_anomaly_%'"""
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  //Converts ResultSet object to JSON
  def convertResultSetIntoJSON(resultSet: ResultSet, customColumn: String): JSONArray = {
    val jsonArray: JSONArray = new JSONArray()
    val timeStamps: List[String] = new HbaseReadTest().getTimeStamps("timestamp", "Dathena:UserClientAnomaly", "user_client_anomaly", "Anomaly", "TotalAnomaly")
    val totalAnomaly: List[String] = new HbaseReadTest().getTimeStamps("ActiveDirectoryAtRisk", "Dathena:UserClientAnomaly", "user_client_anomaly", "Anomaly", "TotalDocumentsAtRisk")
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
              if (getUserClientPreviousValues(timeStamps(1).toString, "TotalAnomaly") > (columnValue.toString).toLong)
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1

            println(timeStamps.size)
            //Adding custom object
            if (timeStamps.nonEmpty)
            {
              val jsonValue: JSONArray = new JSONArray()
              var occurence: Int = 1
              for (i <- totalAnomaly.reverse)
              {
                println(i)
                val obj2: JSONObject = new JSONObject()
		val tempValue: Long = Math.round(i.toFloat)
                obj2.put("docs", tempValue)
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
              obj.put("User Client Data Access Anomaly Trend", jsonValue)
            }
          }

          if (columnName == "Client Data at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Documents")
            if (timeStamps.size >= 2)
            {
              if (getUserClientPreviousValues(timeStamps(1).toString, "TotalDocumentsAtRisk") > (columnValue.toString).toLong)
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }

          if (columnName == "Security Settings at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Windows Active Directory Group")
            if (timeStamps.size >= 2)
            {
              if (getUserClientPreviousValues(timeStamps(1).toString, "TotalActiveDirectoryAtRisk") < (columnValue.toString).toLong)
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
  //*****************END******************

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

  def getUserClientPreviousValues(ts: String, column: String): Long = {
    val connection: Connection = Common.getConnection(ts)
    //println(ts)
    val sql: String = "select TO_NUMBER(\"" + column + "\") from \"Dathena:UserClientAnomaly\" where \"key\" = 'user_client_anomaly'"
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
