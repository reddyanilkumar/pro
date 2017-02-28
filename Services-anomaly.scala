package io.dathena.services

import scala.collection.mutable.ListBuffer
import scala.io.Source._

import java.sql.{Connection, PreparedStatement, ResultSet}

import org.json.{JSONArray, JSONObject}

import io.dathena.tools.HbaseReadTest

class AnomalyClient {

  // FIXME: Read from Dathena.conf
  val hostnames: List[String] = fromFile("hostnames").getLines.toList
  val hostname: String = hostnames(3).split('=')(1).trim
  var updatevalue3: UpdateData = new UpdateData()

  //API-1 :
  //*****************START****************
  def getRiskAnomaly(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String =
      """SELECT
          "key" AS "name",
          TO_NUMBER("Risk") AS "value"
	 FROM "Dathena:RiskAnomaly""""
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()

    val jsonArray: JSONArray = new JSONArray()
    var documents: Long = 0
    var users: Long = 0
    while (rst.next())
    {
      if (!(rst.getString("name") contains "_"))
      {
        val jsonObject: JSONObject = new JSONObject()
          .put("name", rst.getString("name"))
          .put("value", rst.getLong("value"))

        if (rst.getString("name") == "access rights anomaly" || rst.getString("name") == "client data access anomaly")
        {
          users = users + rst.getLong("value")
        }

        jsonArray.put(jsonObject)
      }
      else
      {
        documents = documents + rst.getLong("value")
      }
    }

    val tempMap: Map[String, Long] = Map("Users At Risk" -> users, "Documents Risk" -> documents)
    for ((k, v) <- tempMap)
    {
      val jsonObject: JSONObject = new JSONObject()
        .put("name", k)
        .put("value", v)

      jsonArray.put(jsonObject)
    }

    connection.close()
    return jsonArray
  }

  //Converts ResultSet object to JSON
  def convertResultSetIntoJSON(resultSet: ResultSet, customColumn: String): JSONArray = {
    val jsonArray: JSONArray = new JSONArray()
    val timeStamps: List[String] = new HbaseReadTest().getTimeStamps("timestamp", "Dathena:ManageAnomaly", "client_anomaly", "AnomalyClient", "TotalAnomaly")
    val totalAnomaly: List[String] = new HbaseReadTest().getTimeStamps("totalanomaly", "Dathena:ManageAnomaly", "client_anomaly", "AnomalyClient", "TotalAnomaly")
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
            if (timeStamps.size >= 2 && getClientRepoPreviousValues(timeStamps(1).toString, "TotalAnomaly") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
            obj1.put("trend", trend)
            columnValue = obj1

            if (timeStamps.nonEmpty)
            {
              val jsonValue: JSONArray = new JSONArray()
              var occurence: Int = 1
              for (i <- totalAnomaly.reverse)
              {
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
              obj.put("User Client Data Access Anomaly Trend", jsonValue)
            }
          }

          if (columnName == "Document at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Documents")
            if (timeStamps.size >= 2 && getClientRepoPreviousValues(timeStamps(1).toString, "TotalDocumentsAtRisk") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }

          if (columnName == "Active Directory at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Active Directory Group")
            if (timeStamps.size >= 2 && getClientRepoPreviousValues(timeStamps(1).toString, "TotalActiveDirectoryAtRisk") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
            obj1.put("trend", trend)
            obj1.put("trend", trend)
            columnValue = obj1
          }
        }

        if (customColumn == "ADGroup" && columnName == "Windows User Account")
        {
          obj.put("id", getGUID(columnValue.toString))
          val groupList: Array[String] = getADGroups(columnValue.toString).split(',')
          var userGroups: String = ""
          for (group <- groupList)
          {
            val groupNameList: Array[String] = group.split('=')
            if (groupNameList(0) == "CN")
            {
              userGroups = userGroups + groupNameList(1) + ","
            }
          }
          columnValue = userGroups.dropRight(1)
          columnName = "Active Directory Group"
          obj.put("Confidentiality at Risk", "Banking Secrecy")
        }

        if (columnName == "User Access Right Accuracy")
        {
          columnValue = columnValue.toString.toFloat.asInstanceOf[AnyRef]
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

  //*****************END******************

  //API-2 :
  //*****************START****************
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

  //*****************END******************

  def getClientRepoPreviousValues(ts: String, column: String): Long = {
    val connection: Connection = Common.getConnection(ts)
    val sql: String = "select TO_NUMBER(\"" + column + "\") from \"Dathena:ManageAnomaly\" where \"key\" = 'client_anomaly'"
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

  def getHighRiskUsers(filter: String, customAttribute: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = """SELECT COUNT(1) FROM "Dathena:Anomalies"""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = """SELECT "Review Status", "key" AS "Windows User Account", "1: files" AS "Document at Risk", "2: directory" AS "Folder at Risk" FROM "Dathena:Anomalies" WHERE "1: files" IS NOT NULL AND "Review Status" LIKE ?"""
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = """SELECT "Review Status", "key" AS "Windows User Account", "1: files" AS "Document at Risk", "2: directory" AS "Folder at Risk" FROM "Dathena:Anomalies" WHERE "1: files" IS NOT NULL"""
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, customAttribute)
    connection.close()
    return response
  }

  def getHighRiskUsersCount(): Int = {
    val connection: Connection = Common.getConnection()
    val query: String = "select count(*) from \"Dathena:Anomalies\" where \"1: files\" is not null"
    val rst: ResultSet = connection.createStatement().executeQuery(query)
    rst.next()
    val count: Int = rst.getInt(1)
    connection.close()
    return count
  }

  def getHighRiskFolderCount(): Int = {
    val connection: Connection = Common.getConnection()
    val query: String = "select \"2: directory\" from \"Dathena:Anomalies\" where \"1: files\" is not null"
    val rst: ResultSet = connection.createStatement().executeQuery(query)
    var count: Int = 0
    while (rst.next())
    {
      count = count + rst.getString(1).toInt
    }
    connection.close()
    return count
  }

  def getHighRiskDocCount(): Int = {
    val connection: Connection = Common.getConnection()
    val query: String = "select \"1: files\" from \"Dathena:Anomalies\" where \"1: files\" is not null"
    val rst: ResultSet = connection.createStatement().executeQuery(query)
    var count: Int = 0
    while (rst.next())
    {
      count = count + rst.getString(1).toInt
    }
    connection.close()
    return count
  }

  //*****************END******************

  //API-3,4
  def getAllGUID(user: String): List[String] = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select DISTINCT(\"objectGUID\") from \"Dathena:USERS\""
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, user)
    val rst: ResultSet = query.executeQuery()
    var guid: ListBuffer[String] = ListBuffer[String]()
    while (rst.next())
    {
      guid += rst.getString("objectGUID")
    }
    connection.close()
    return guid.toList
  }

  def getName(user: String): String = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"key\" from \"Dathena:USERS\" where \"objectGUID\" = ?"
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, user)
    val rst: ResultSet = query.executeQuery()
    var name: String = ""
    while (rst.next())
    {
      name = rst.getString(1)
    }
    connection.close()
    return name
  }

  //*****************END******************

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

  //API-CLIENT DATA REPO
  def getClientDataRepoFirstTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String =
      """
      SELECT
        TO_NUMBER("ActiveDirectoryAtRisk") AS "Active Directory Group at Risk",
        TO_NUMBER("Accuracy") * 100 AS "User Access Right Accuracy",
        TO_NUMBER("UserAnomaly") AS "User Anomaly",
        "Confidentiality" AS "Confidentiality at Risk",
        TO_NUMBER("FolderAtRisk") AS "Folder at Risk"
      FROM "Dathena:ManageAnomaly"
      WHERE
        "key" LIKE 'client_anomaly_%'
      """
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  def getClientDataRepoSecondTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"TotalAnomaly\") as \"Total Anomaly\",TO_NUMBER(\"TotalDocumentsAtRisk\") as \"Document at Risk\",TO_NUMBER(\"TotalActiveDirectoryAtRisk\") as \"Active Directory at Risk\"  from \"Dathena:ManageAnomaly\" where \"key\" = 'client_anomaly'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "ClientDataSecond")
    connection.close()
    return response
  }

  //Summary

  def getClientDataHighRiskUsers(filter: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = "select \"owner\" as \"Windows User Account\",TO_NUMBER(\"DocumentsAtRisk\") as \"Document at Risk\",\"Confidentiality\",TO_NUMBER(\"FolderAtRisk\") as \"Folder at Risk\",\"SecurityInFault\" as \"Security in Fault\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:ManageAnomaly\" where \"key\" like 'summary_client_anomaly_%' and \"ReviewStatus\" like ?"
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = "select \"owner\" as \"Windows User Account\",TO_NUMBER(\"DocumentsAtRisk\") as \"Document at Risk\",\"Confidentiality\",TO_NUMBER(\"FolderAtRisk\") as \"Folder at Risk\",\"SecurityInFault\" as \"Security in Fault\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:ManageAnomaly\" where \"key\" like 'summary_client_anomaly_%'"
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
}
