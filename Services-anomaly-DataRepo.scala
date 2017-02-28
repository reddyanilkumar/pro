package io.dathena.services

import scala.io.Source._

import java.sql.{Connection, DriverManager, PreparedStatement, ResultSet}
import java.util.Properties

import org.json.{JSONArray, JSONObject}

import io.dathena.tools.HbaseReadTest

class AnomalyClientDocumentRepo {

  val hostnames: List[String] = fromFile("hostnames").getLines.toList
  val hostname: String = hostnames(3).split('=')(1).trim
  var updatevalue3: UpdateData = new UpdateData()

  //API-1 :
  //*****************START****************
  def getRiskAnomaly(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"key\" as \"name\",\"Risk\" as \"value\" from \"Dathena:RiskAnomaly\""
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  def getHighRiskUsers(filter: String, customAttribute: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = "select \"Review Status\",\"key\" as \"Windows User Account\",\"1: files\" as \"Document at Risk\",\"2: directory\" as \"Folder at Risk\" from \"Dathena:Anomalies\" where \"1: files\" is not null and \"Review Status\" like ?"
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = "select \"Review Status\",\"key\" as \"Windows User Account\",\"1: files\" as \"Document at Risk\",\"2: directory\" as \"Folder at Risk\" from \"Dathena:Anomalies\" where \"1: files\" is not null "
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, customAttribute)
    connection.close()
    return response
  }

  //Converts ResultSet object to JSON
  def convertResultSetIntoJSON(resultSet: ResultSet, customColumn: String): JSONArray = {
    val jsonArray: JSONArray = new JSONArray()
    val timeStamps: List[String] = new HbaseReadTest().getTimeStamps("timestamp", "Dathena:DocumentRepoAnomaly", "DocumentRepo", "Anomaly", "TotalAnomaly")
    val totalAnomaly: List[String] = new HbaseReadTest().getTimeStamps("totalanomaly", "Dathena:DocumentRepoAnomaly", "DocumentRepo", "Anomaly", "TotalUserAnomaly")
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
            obj1.put("type", "Documents")
            if (timeStamps.size >= 2 && getDataRepoPreviousValues(timeStamps(1).toString, "TotalAnomaly") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }

          if (columnName == "Total User at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Windows User Account")
            if (timeStamps.size >= 2 && getDataRepoPreviousValues(timeStamps(1).toString, "TotalUserAnomaly") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
            obj1.put("trend", trend)
            columnValue = obj1

            //Adding custom object
            if (timeStamps.nonEmpty)
            {
              val jsonValue: JSONArray = new JSONArray()
              var occurrence: Int = 1
              for (i <- totalAnomaly.reverse)
              {
                val obj2: JSONObject = new JSONObject()
		val tempValue: Long = Math.round(i.toFloat)
                obj2.put("users", tempValue)
                obj2.put("occurence", occurrence)
                occurrence += 1
                var occurrence_type: String = "medium"
                if (tempValue < 33)
                {
                  occurrence_type = "low"
                }
                else if (tempValue >= 66)
                {
                  occurrence_type = "high"
                }
                obj2.put("type", occurrence_type)
                jsonValue.put(obj2)
              }
              obj.put("Document Repository Anomaly Trend", jsonValue)
            }
          }

          if (columnName == "Total Folder at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Folders")
            if (timeStamps.size >= 2 && getDataRepoPreviousValues(timeStamps(1).toString, "TotalFolderAnomaly") > (columnValue.toString).toLong)
            {
              trend = "down"
            }
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

        if (columnName == "percentage")
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

  //*****************END******************

  //API-3,4
  def getGUID(user: String): String = {
    val connection: Connection = Common.getConnection()
    println("user:" + user)
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

  def getDataRepoPreviousValues(ts: String, column: String): Long = {
    val connection: Connection = Common.getConnection(ts)
    val sql: String = "select TO_NUMBER(\"" + column + "\") from \"Dathena:DocumentRepoAnomaly\" where \"key\" = 'DocumentRepo'"
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

  def getHighRiskUsersCount(): Int = {
    val connection: Connection = Common.getConnection()
    val query: String = "select count(*) from \"Dathena:Anomalies\" where \"1: files\" is not null"
    val rst: ResultSet = connection.createStatement().executeQuery(query)
    rst.next()
    val count: Int = rst.getInt(1)
    connection.close()
    return count
  }

  //*****************END******************

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

  //API-2 :
  //*****************START****************
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

  //API- DATA REPO
  def getDataRepoFirstTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"FoldersAmount\") as \"Folder at Risk\",\"Confidentiality\" as \"Confidentiality at Risk\",TO_NUMBER(\"FilesAmount\") as \"Document at Risk\",TO_NUMBER(\"ownerAmount\") as \"User Anomaly\"  from \"Dathena:DocumentRepoAnomaly\" where \"key\" like 'DocumentRepo_%'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  def getDataRepoSecondTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"TotalAnomaly\") as \"Total Anomaly\",TO_NUMBER(\"TotalFolderAnomaly\") as \"Total Folder at Risk\",TO_NUMBER(\"TotalUserAnomaly\") as \"Total User at Risk\" from \"Dathena:DocumentRepoAnomaly\" where \"key\" = 'DocumentRepo'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "ClientDataSecond")
    connection.close()
    return response
  }

  def getDocumentRepo(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"Category\" as \"name\",\"percentage\" from \"Dathena:DocumentRepoAnomaly\" where \"key\" like 'summarycategory_DocumentRepo_%'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  //Summary
  def getDataHighRiskUsers(filter: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = "select \"User\" as \"Windows User Account\",TO_NUMBER(\"FoldersAmount\") as \"Folder at Risk\",\"Confidentiality\",TO_NUMBER(\"FilesAmount\") as \"Document at Risk\",\"SecurityInFault\" as \"Security in Fault\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:DocumentRepoAnomaly\" where \"key\" like 'summary_DocumentRepo_%' and \"ReviewStatus\" like ? LIMIT 100"
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = "select \"User\" as \"Windows User Account\",TO_NUMBER(\"FoldersAmount\") as \"Folder at Risk\",\"Confidentiality\",TO_NUMBER(\"FilesAmount\") as \"Document at Risk\",\"SecurityInFault\" as \"Security in Fault\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:DocumentRepoAnomaly\" where \"key\" like 'summary_DocumentRepo_%' LIMIT 100"
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
}
