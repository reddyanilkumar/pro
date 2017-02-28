package io.dathena.services

import scala.io.Source._

import java.sql.{Connection, PreparedStatement, ResultSet}

import org.json.{JSONArray, JSONObject}

import io.dathena.tools.HbaseReadTest

class AnomalyIAMClient {

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
  def getADGroupClientFirstTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = """
      SELECT
        TO_NUMBER("ActiveDirectoryAtRisk") AS "Active Directory at Risk",
        TO_NUMBER("Accuracy") * 100 AS "User Access Right Accuracy",
        "Confidentiality" AS "Confidentiality at Risk",
        TO_NUMBER("FoldersAmount") AS "Folder at Risk",
        TO_NUMBER("GroupAmount") AS "AD Group Anomaly"
      FROM "Dathena:ADGroupAnomaly"
      WHERE
        "key" LIKE 'group_client_anomaly_%'
      """
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }

  //*****************END******************

  def getADGroupClientSecondTable(): JSONArray = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select TO_NUMBER(\"TotalGroupAnomaly\") as \"Total Anomaly\",TO_NUMBER(\"TotalDocumentsAtRisk\") as \"Document at Risk\",TO_NUMBER(\"TotalUserAnomaly\") as \"Total Users at Risk\"  from \"Dathena:ADGroupAnomaly\" where \"key\" = 'group_client_anomaly'"
    val query: PreparedStatement = connection.prepareStatement(sql)
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "ClientDataSecond")
    connection.close()
    return response
  }

  //Converts ResultSet object to JSON
  def convertResultSetIntoJSON(resultSet: ResultSet, customColumn: String): JSONArray = {
    val jsonArray: JSONArray = new JSONArray()
    val timeStamps: List[String] = new HbaseReadTest().getTimeStamps("timestamp", "Dathena:ADGroupAnomaly", "group_client_anomaly", "AD_ClientAnomaly", "TotalUserAnomaly")
    println("size : " + timeStamps)
    val totalAnomaly: List[String] = new HbaseReadTest().getTimeStamps("totalGroupAnomaly", "Dathena:ADGroupAnomaly", "group_client_anomaly", "AD_ClientAnomaly", "TotalUserAnomaly")
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
          columnName = "id"
          columnValue = getGUID(columnValue.toString)
        }

        if (customColumn == "ClientDataSecond")
        {
          if (columnName == "Total Anomaly")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Windows Active Directory Group")
            println(timeStamps.size)
            if (timeStamps.size >= 2)
            {
              if (getADGroupPreviousValues(timeStamps(1).toString, "TotalGroupAnomaly") > (columnValue.toString).toLong)
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
              var occurrence: Int = 1
              for (i <- totalAnomaly.reverse)
              {
                println(i)
	        val tempValue: Long = Math.round(i.toFloat)
                val obj2: JSONObject = new JSONObject()
                obj2.put("AD Group", tempValue)
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
              obj.put("Anomaly Trend", jsonValue)
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
              if (getADGroupPreviousValues(timeStamps(1).toString, "TotalDocumentsAtRisk") > (columnValue.toString).toLong)
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }

          if (columnName == "Total Users at Risk")
          {
            val obj1: JSONObject = new JSONObject()
            var trend: String = "up"
            obj1.put("value", columnValue)
            obj1.put("type", "Windows User Account")
            if (timeStamps.size >= 2)
            {
              if (getADGroupPreviousValues(timeStamps(1).toString, "TotalUserAnomaly") > (columnValue.toString).toLong)
              {
                trend = "down"
              }
            }
            obj1.put("trend", trend)
            columnValue = obj1
          }
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

  //*****************END******************

  def getGUID(user: String): String = {
    val connection: Connection = Common.getConnection()
    val sql: String = "select \"objectGUID\" from \"Dathena:USERS\" where \"key\" = ?"
    val query: PreparedStatement = connection.prepareStatement(sql)
    query.setString(1, user)
    val rst: ResultSet = query.executeQuery()
    rst.next()
    val guid: String = rst.getString(1)
    connection.close()
    return guid
  }

  def getADGroupPreviousValues(ts: String, column: String): Long = {
    val connection: Connection = Common.getConnection(ts)
    //println(ts)
    val sql: String = "select TO_NUMBER(\"" + column + "\") from \"Dathena:ADGroupAnomaly\" where \"key\" = 'group_client_anomaly'"
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

  //Summary
  def getADGroupHighRiskUsers(filter: String): JSONArray = {
    val connection: Connection = Common.getConnection()
    var sql: String = "select count(1) from \"Dathena:Anomalies\""
    var query: PreparedStatement = connection.prepareStatement(sql)
    if (filter != "all")
    {
      sql = "select TO_NUMBER(\"id\") as \"id\",TO_NUMBER(\"FilesAmount\") as \"Document at Risk\",\"Confidentiality\" as \"Confidentiality at Risk\",TO_NUMBER(\"FoldersAmount\") as \"Folder at Risk\",\"Group\" as \"Active Directory Group\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:ADGroupAnomaly\" where \"key\" like 'summary_group_client_anomaly_%' and \"ReviewStatus\" like ?"
      query = connection.prepareStatement(sql)
      query.setString(1, filter)
    }
    else
    {
      sql = "select TO_NUMBER(\"id\") as \"id\",TO_NUMBER(\"FilesAmount\") as \"Document at Risk\",\"Confidentiality\" as \"Confidentiality at Risk\",TO_NUMBER(\"FoldersAmount\") as \"Folder at Risk\",\"Group\" as \"Active Directory Group\",\"ReviewStatus\" as \"Review Status\" from \"Dathena:ADGroupAnomaly\" where \"key\" like 'summary_group_client_anomaly_%'"
      query = connection.prepareStatement(sql)
    }
    val rst: ResultSet = query.executeQuery()
    val response: JSONArray = convertResultSetIntoJSON(rst, "")
    connection.close()
    return response
  }
}
