package com.okta.bulkload;

import static com.okta.bulkload.BulkLoader.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.math.BigInteger;
import org.apache.commons.csv.*;
import org.apache.http.Header;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.util.EntityUtils;
import org.json.*;

public class BulkLoader {
    final static Properties configuration = new Properties();
    protected static AtomicInteger successCount = new AtomicInteger(0), errorCount = new AtomicInteger(0);
    protected static CSVPrinter errorRecordPrinter, rateLimitFailurePrinter, successRecordPrinter;
    protected static volatile boolean noMoreRecordsBeingAdded = false;
    protected static volatile boolean errorHeaderWritten = false;
    protected static String[] successHeaders = null;
	protected static String[] errorHeaders = null;
    protected static String csvFileArg = null;

    public static void main(String args[]) throws Exception{
        System.out.println("Start : "+new Date());
        System.out.println();
        long startTime = System.currentTimeMillis();
        
        if (args.length < 2)
        {
            System.out.println(new Date() + " : **ERROR** : Missing configuration file argument");
            System.out.println("Run using following command : ");
            System.out.println("java -jar bulk_load.jar <config_file> <csv_file_location>");
            System.exit(-1);
        }
        try{
            configuration.load(new FileInputStream(args[0]));
            csvFileArg = args[1];
        }
        catch(Exception e){
            System.out.println("Error reading configuration. Exiting...");
            System.exit(-1);
        }
        String filePrefix = csvFileArg.substring(0,csvFileArg.lastIndexOf('.'));	
        String successFile = filePrefix+"_success.csv";
		String errorFile = filePrefix+"_reject.csv";
        String rateLimitFile = filePrefix+"_replay.csv";
        errorHeaders = (configuration.getProperty("csvHeaderRow")+",errorCode,errorCause").split(",");
		successHeaders = (configuration.getProperty("csvHeaderRow")+",id,status").split(",");
        int numConsumers = Integer.parseInt(configuration.getProperty("numConsumers", "1"));
        int bufferSize = Integer.parseInt(configuration.getProperty("bufferSize", "10000"));
        
        CSVFormat errorFormat = CSVFormat.RFC4180.withDelimiter(',').withQuote('"').withQuoteMode(QuoteMode.ALL).withHeader(errorHeaders); 
		CSVFormat successFormat = CSVFormat.RFC4180.withDelimiter(',').withQuote('"').withQuoteMode(QuoteMode.ALL).withHeader(successHeaders);        		
        successRecordPrinter = new CSVPrinter(new FileWriter(successFile),successFormat);
		errorRecordPrinter = new CSVPrinter(new FileWriter(errorFile),errorFormat);
        rateLimitFailurePrinter = new CSVPrinter(new FileWriter(rateLimitFile),errorFormat);
        successRecordPrinter.flush();		
		errorRecordPrinter.flush();
        rateLimitFailurePrinter.flush();
        
        BlockingQueue myQueue = new LinkedBlockingQueue(bufferSize);
        
        Producer csvReadWorker = new Producer(myQueue);
        Thread producer = new Thread(csvReadWorker);
        producer.start();
        Thread.sleep(500);//Give the queue time to fill up
        
        Thread[] consumers = new Thread[numConsumers];
        for (int i = 0; i < numConsumers; i++){
            Consumer worker = new Consumer(myQueue);
            consumers[i] = new Thread(worker);
            consumers[i].start();
        }
        
        producer.join();
        for (int i = 0; i < numConsumers; i++)
            consumers[i].join();

        //close the errorPrinter
        errorRecordPrinter.close();
        
        System.out.println();
        System.out.println("Successfully added "+successCount+" user(s)");
        System.out.println("Error in processing "+errorCount+" user(s)");
        System.out.println();
        System.out.println("Done : "+new Date());
        long endTime = System.currentTimeMillis();
        long duration = (endTime - startTime)/1000;
        System.out.println("Total time taken = "+duration+" seconds");
    }
}

class Producer implements Runnable {
    private final BlockingQueue queue;
    private final CSVFormat format;
    Producer(BlockingQueue q) { 
        queue = q; 
        format = CSVFormat.RFC4180.withHeader().withDelimiter(',');        
    }
    public void run() {
        try {
            //initialize the CSVParser object
            CSVParser parser = new CSVParser(new FileReader(csvFileArg), format);
            for(CSVRecord record : parser)           
                queue.put(record);
            parser.close();
        } catch (Exception excp) { 
            System.out.println(excp.getLocalizedMessage());
        } finally {
            noMoreRecordsBeingAdded = true;
        }
    }
}
   
 class Consumer implements Runnable {
    private final BlockingQueue queue;
    private final String org;
    private final String apiToken;
    private final String csvHeaderRow;
    private final String[] csvHeaders;
    private final String csvLoginField;
    private final String csvPasswordField;
    private final String saltOrder;
    private final String activateUsers;
    private final String groupIDs;
    private final Integer rateLimitThreshold;

    private final CloseableHttpClient httpclient;
    Consumer(BlockingQueue q) { 
        queue = q; 
        org = configuration.getProperty("org");
        apiToken = configuration.getProperty("apiToken");
        csvHeaderRow = configuration.getProperty("csvHeaderRow");
        csvHeaders = csvHeaderRow.split(",");
        csvLoginField = configuration.getProperty("csvLoginField");
        csvPasswordField = configuration.getProperty("csvPasswordField");
        saltOrder = configuration.getProperty("saltOrder");
        activateUsers = configuration.getProperty("activateUsers");
        groupIDs = configuration.getProperty("groupIDs");
        rateLimitThreshold = Integer.valueOf(configuration.getProperty("rateLimitThreshold"));

        RequestConfig requestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
        httpclient = HttpClientBuilder.create()
                .setRetryHandler(new DefaultHttpRequestRetryHandler(3, false))
                .setDefaultRequestConfig(requestConfig)
                .build();
    }
    public void run() {
        try {
            while (true) { 
                if (noMoreRecordsBeingAdded && queue.isEmpty())
                    Thread.currentThread().interrupt();
                consume(queue.take());
            }
        } catch (InterruptedException ex) { 
            //System.out.println("Finished processing for this thread");
        } catch (Exception excp) { 
            System.out.println(excp.getLocalizedMessage());//This consumer thread will abort execution
        }     
    }
   
    void consume(Object record) throws Exception{

        CSVRecord csvRecord = (CSVRecord)record;
        JSONObject user = new JSONObject();
        JSONObject profile = new JSONObject();
        JSONObject responseJSON = new JSONObject();
        JSONObject credentials = new JSONObject();
        JSONObject valueObj = new JSONObject();
        JSONObject hashObj = new JSONObject();
        JSONObject passwordObj = new JSONObject();
        JSONObject hook = new JSONObject();
        int rateLimit,rateLimitRemaining;
        long limitResetsAt;

        String subshaValue = new String(), salt, hashpswd, userId, shaAlgo;
        int index, arrayLength;
        byte[] comboValue, saltOutput, hashOutput;

        //Add username
        profile.put("login", csvRecord.get(csvLoginField));
        user.put("groupIds", new JSONArray());

        //Flesh out rest of profile
        for (String headerColumn:csvHeaders){
            if (!headerColumn.equalsIgnoreCase(csvPasswordField)){
                if(configuration.getProperty("csvHeader."+headerColumn) != null){
                    profile.put(configuration.getProperty("csvHeader."+headerColumn),csvRecord.get(headerColumn));
                }
            }
        }

        if(groupIDs != null){
            String[] groupsList = groupIDs.split("\\,");
            for(int i=0; i<groupsList.length;i++){
                user.getJSONArray("groupIds").put(groupsList[i]);
            }
        }

        String shaValue = csvRecord.get(csvPasswordField);
        index = shaValue.indexOf("}");
        subshaValue = shaValue.substring(index + 1);
        shaAlgo = shaValue.substring(0, index + 1);

        if (shaAlgo.startsWith("{SSHA")) {
            comboValue = Base64.getDecoder().decode(subshaValue);
            arrayLength = comboValue.length;

            saltOutput = new byte[8];
            hashOutput = new byte[arrayLength - 8];

            if (saltOrder.toLowerCase().matches("prefix")) {
                System.arraycopy(comboValue, 0, saltOutput, 0, 8);
                System.arraycopy(comboValue, 8, hashOutput, 0, 64);
            } else {
                System.arraycopy(comboValue, arrayLength - 8, saltOutput, 0, 8);
                System.arraycopy(comboValue, 0, hashOutput, 0, arrayLength - 8);
            }
            hashpswd = Base64.getMimeEncoder().encodeToString(hashOutput);
            salt = Base64.getMimeEncoder().encodeToString(saltOutput);
            hashpswd = hashpswd.replace("\r\n", "");
            valueObj.put("value", hashpswd);
            valueObj.put("salt", salt);
            valueObj.put("saltOrder", saltOrder);
        }

        valueObj.put("algorithm", "SHA-1");
        hashObj.put("hash", valueObj);
        passwordObj.put("password", hashObj);
        user.put("credentials", passwordObj);


        user.put("profile", profile);

        // Build JSON payload
        StringEntity data = new StringEntity(user.toString(),ContentType.APPLICATION_JSON);

        // build http request and assign payload data
        HttpUriRequest request = RequestBuilder
                .post("https://"+org+"/api/v1/users?activate="+activateUsers)
                .setHeader("Authorization", "SSWS " + apiToken)
                .setEntity(data)
                .build();
        CloseableHttpResponse httpResponse = null;
        try{
            httpResponse = httpclient.execute(request);
            int responseCode = httpResponse.getStatusLine().getStatusCode();
            rateLimit = Integer.parseInt(httpResponse.getFirstHeader("X-Rate-Limit-Limit").getValue());
            rateLimitRemaining = Integer.parseInt(httpResponse.getFirstHeader("X-Rate-Limit-Remaining").getValue());
            limitResetsAt = Long.parseLong(httpResponse.getFirstHeader("x-rate-limit-reset").getValue());

            //if remaining API calls are less than rateLimitThreshold(config property), put this thread into sleep till limit is reset (adds another 5 secs)
            if((rateLimitRemaining*100)/rateLimit < rateLimitThreshold){
                long timeToSleep = Math.abs(limitResetsAt - (System.currentTimeMillis()/1000)) + 5;
                Thread.sleep(timeToSleep*1000);
            }

            responseJSON = new JSONObject(EntityUtils.toString(httpResponse.getEntity()));
            //Rate limit exceeded, hold off processing for this thread till the limit is reset
            if (responseCode == 429){//Retry after appropriate time
                handleErrorResponse(true, responseCode, responseJSON, csvRecord, null);

                //Put this thread to sleep for at least 5 seconds
                long timeToSleep = Math.abs(limitResetsAt - (System.currentTimeMillis()/1000)) + 5;
                Thread.sleep(timeToSleep*1000);
            }
            else if (responseCode != 200){//Non-success
                handleErrorResponse(false, responseCode, responseJSON, csvRecord, "");
            }
            else{
				handleSuccessResponse(true, responseCode, responseJSON, csvRecord, "");
                successCount.getAndIncrement();				
            if (successCount.get()!=0 && successCount.get()%100==0)System.out.print(".");
			}
        } catch(Exception e){//Issue with the connection. Let's not lose the consumer thread
            handleErrorResponse(false, 400, responseJSON, csvRecord, e.getLocalizedMessage());
        }finally{
            if (null != httpResponse)
                httpResponse.close();
        }
    }
    
    void handleErrorResponse(boolean isRateLimitError, int responseCode, JSONObject response, CSVRecord csvRecord, String exceptionMessage)throws IOException{
        String errorCode, errorCause;
        try{
            errorCode = response.getString("errorCode");
            errorCause = response.getJSONArray("errorCauses").getJSONObject(0).getString("errorSummary");
        }catch (Exception e){
            //Can't get error details out of JSON. Assume error that did not result from data
            errorCode = "HTTP Response code : "+responseCode;
            errorCause = exceptionMessage;
        }
        Map values = csvRecord.toMap();
        values.put("errorCode", errorCode);
        values.put("errorCause", errorCause);
        if(isRateLimitError)
        {
            synchronized(rateLimitFailurePrinter){
                for (String header : errorHeaders)
                    rateLimitFailurePrinter.print(values.get(header));//Got an error for this row - write it to error file
                rateLimitFailurePrinter.println();
                rateLimitFailurePrinter.flush();
            }
        }
        else{
            synchronized(errorRecordPrinter){
                for (String header : errorHeaders)
                    errorRecordPrinter.print(values.get(header));//Got an error for this row - write it to error file
                errorRecordPrinter.println();
                errorRecordPrinter.flush();
            }
        }
        errorCount.getAndIncrement();
    }
	
	void handleSuccessResponse(boolean isSuccess, int responseCode, JSONObject response, CSVRecord csvRecord, String exceptionMessage)throws IOException{
        String id, status;
        try{
            id = response.getString("id");
            status = response.getString("status");
        }catch (Exception e){
            //Can't get error details out of JSON. Assume error that did not result from data
            id = "HTTP Response code : "+responseCode;
            status = exceptionMessage;
        }
        Map values = csvRecord.toMap();
        values.put("id", id);
        values.put("status", status);
        if(isSuccess)
        {
            synchronized(successRecordPrinter){
                for (String header : successHeaders)
                    successRecordPrinter.print(values.get(header));//Got an error for this row - write it to error file
                successRecordPrinter.println();
                successRecordPrinter.flush();
            }
        }
    }
}
