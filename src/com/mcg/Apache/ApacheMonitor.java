package com.mcg.Apache;

import com.dynatrace.diagnostics.pdk.*;
import com.dynatrace.diagnostics.pdk.PluginEnvironment.Host;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.util.Collection;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.util.EncodingUtil;

public class ApacheMonitor implements Monitor {

	private static final int READ_CHUNK_SIZE = 1024;

	// configuration constants
	private static final String CONFIG_PROTOCOL = "protocol";
	private static final String CONFIG_PATH = "path";
	private static final String CONFIG_HTTP_PORT = "httpPort";
	private static final String CONFIG_HTTPS_PORT = "httpsPort";
	private static final String CONFIG_METHOD = "method";
	private static final String CONFIG_POST_DATA = "postData";
	private static final String CONFIG_USER_AGENT = "userAgent";
	private static final String CONFIG_HTTP_VERSION = "httpVersion";
	private static final String CONFIG_DT_TAGGING = "dtTagging";
	private static final String CONFIG_MAX_REDIRECTS = "maxRedirects";

	private static final String CONFIG_SERVER_AUTH = "serverAuth";
	private static final String CONFIG_SERVER_USERNAME = "serverUsername";
	private static final String CONFIG_SERVER_PASSWORD = "serverPassword";

	private static final String CONFIG_USE_PROXY = "useProxy";
	private static final String CONFIG_PROXY_HOST = "proxyHost";
	private static final String CONFIG_PROXY_PORT = "proxyPort";
	private static final String CONFIG_PROXY_AUTH = "proxyAuth";
	private static final String CONFIG_PROXY_USERNAME = "proxyUsername";
	private static final String CONFIG_PROXY_PASSWORD = "proxyPassword";

	// measure constants
	private static final String METRIC_GROUP = "Apache Monitor";
	private static final String MSR_TOTAL_ACCESSES = "TotalAccesses";
	private static final String MSR_TOTAL_MBYTES = "TotalBytes";
	private static final String MSR_CPU_LOAD = "CPULoad";
	private static final String MSR_UPTIME = "Uptime";
	private static final String MSR_REQ_PER_SEC = "ReqPerSec";
	private static final String MSR_BYTES_PER_SEC = "BytesPerSec";
	private static final String MSR_BYTES_PER_REQ = "BytesPerReq";
	private static final String MSR_BUSY_WORKERS = "BusyWorkers";
	private static final String MSR_IDLE_WORKERS = "IdleWorkers";
	private static final String MSR_WORKERS_UTILIZATION = "WorkersUtilization";

	private static final String METRIC_SB_GROUP = "Apache Scoreboard";
	private static final String MSR_SB_WAITING_FOR_CONNECTION = "Waiting for Connection";
	private static final String MSR_SB_STARTING_UP = "Starting up";
	private static final String MSR_SB_READING_REQUEST = "Reading Request";
	private static final String MSR_SB_SENDING_REPLY = "Sending Reply";
	private static final String MSR_SB_KEEPALIVE = "Keepalive (read)";
	private static final String MSR_SB_DNS_LOOKUP = "DNS Lookup";
	private static final String MSR_SB_CLOSING_CONNECTION = "Closing connection";
	private static final String MSR_SB_LOGGING = "Logging";
	private static final String MSR_SB_GRACEFULLY_FINISHING = "Gracefully finishing";
	private static final String MSR_SB_IDLE_CLEANUP_OF_WORKER = "Idle cleanup of worker";
	private static final String MSR_SB_OPEN_SLOT = "Open slot with no current process";
	
	private static final Logger log = Logger.getLogger(ApacheMonitor.class.getName());
	
	private static class Config {
		String protocol;
		int port;
		String path;
		String method;
		String postData;
		String httpVersion;
		String userAgent;
		int maxRedirects;
		boolean tagging;
		
		// server authentification.
		boolean serverAuth;
		String serverUsername;
		String serverPassword;
		
		// proxy.
		boolean useProxy;
		String proxyHost;
		int proxyPort;
		boolean proxyAuth;
		String proxyUsername;
		String proxyPassword;
	}

	private Config config;

	private HttpClient httpClient;

	@Override
	public Status setup(MonitorEnvironment env) throws Exception {
		Status status = new Status(Status.StatusCode.Success);
		
		// set certstore that we are using.
		/*
		System.setProperty("javax.net.ssl.trustStore", "c:/jssecacerts");
		System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
		*/
		httpClient = new HttpClient(new SimpleHttpConnectionManager());
		config = readConfig(env);
		try {
			env.getHost().getAddress(); // check if host is set
		} catch (NullPointerException npe) {
			status.setStatusCode(Status.StatusCode.ErrorInfrastructure);
			status.setShortMessage("Configuration property not set");
			status.setMessage("Configuration property not set");
			status.setException(npe);
		}
		return status;
	}

	@Override
	public void teardown(MonitorEnvironment env) throws Exception {
		HttpConnectionManager httpConnectionManager = httpClient.getHttpConnectionManager();
		if (httpConnectionManager instanceof SimpleHttpConnectionManager) {
			((SimpleHttpConnectionManager)httpConnectionManager).shutdown();
		}				
	}
	
	private void setMeasurementValue(MonitorEnvironment env, String group, String key, double value) {
		Collection<MonitorMeasure> measures;
		if((measures = env.getMonitorMeasures(group, key)) != null) {
			for(MonitorMeasure measure : measures)
				measure.setValue(value);
		}
	}
	
	private void setMeasurementValue(MonitorEnvironment env, String group, String key, long value) {
		Collection<MonitorMeasure> measures;
		if((measures = env.getMonitorMeasures(group, key)) != null) {
			for(MonitorMeasure measure : measures)
				measure.setValue(value);
		}
	}

	@Override
	public Status execute(MonitorEnvironment env) throws Exception {
		// measurement variables
		long totalAccesses = 0;
		double totalkBytes = 0.0;
		double cpuLoad = 0.0;
		long uptime = 0;
		double reqPerSec = 0.0;
		double bytesPerSec = 0.0;
		double bytesPerReq = 0.0;
		double busyWorkers = 0.0;
		double idleWorkers = 0.0;
		double workersUtilization = 0;
		
		long connectionCloseDelay = 0;
		long firstResponseTime = 0;
		long headerSize = 0;
		int httpStatusCode = 0;
		long inputSize = 0;
		long responseCompleteTime = 0;

		long sbWaitingForConnection = 0;
		long sbStartingUp = 0;
		long sbReadingRequest = 0;
		long sbSendingReply = 0;
		long sbKeepAlive = 0;
		long sbDnsLookup = 0;
		long sbClosingConnection = 0;
		long sbLogging = 0;
		long sbGracefullyFinishing = 0;
		long sbIdleCleanupOfWorker = 0;
		long sbOpenSlot = 0;
		
		boolean verified = false;
		long time;
		Status status = new Status();
		
		// create a HTTP client and method
		HttpMethodBase httpMethod = createHttpMethod(config, env.getHost());
		if (httpMethod == null) {
			status.setStatusCode(Status.StatusCode.ErrorInternal);
			status.setMessage("Unknown HTTP method: " + config.method);
			return status;
		}
		
		// try to set parameters
		try {
			setHttpParameters(httpMethod, config);
			
		} catch (Exception ex) {
			status.setStatusCode(Status.StatusCode.ErrorInternal);
			status.setMessage("Setting HTTP client parameters failed");
			status.setShortMessage(ex == null ? "" : ex.getClass().getSimpleName());
			status.setMessage(ex == null ? "" : ex.getMessage());
			status.setException(ex);
			return status;
		}

		try {
			if (log.isLoggable(Level.FINE))
				log.info("Executing method: " + config.method + ", URI: " + httpMethod.getURI());

			// connect
			time = System.nanoTime();
			httpStatusCode = httpClient.executeMethod(httpMethod);
			firstResponseTime = System.nanoTime() - time;

			// calculate header size
			headerSize = calculateHeaderSize(httpMethod.getResponseHeaders());

			// read response data
			InputStream inputStream = httpMethod.getResponseBodyAsStream();
			
			if (inputStream != null) {
				int bytesRead = 0;
				byte[] data = new byte[READ_CHUNK_SIZE];
				String charset = httpMethod.getResponseCharSet();
				StringBuilder buf = new StringBuilder();
				
				while ((bytesRead = inputStream.read(data)) > 0) {
					buf.append(EncodingUtil.getString(data, 0, bytesRead, charset));
					inputSize += bytesRead;
				}
				responseCompleteTime = System.nanoTime() - time;
				
				if(!buf.toString().toLowerCase().contains("scoreboard")) {
					status.setMessage("Error returned page didn't contain the text scoreboard, returned text: ." + buf.toString());
					status.setShortMessage("Error returned page didn't contain the text scoreboard.");
					status.setStatusCode(Status.StatusCode.ErrorInternal);
					return status;
				}
				
				// Parse out the timers.
				try {
					StringTokenizer st = new StringTokenizer(buf.toString(), "\n");
					while(st.hasMoreTokens()) {
						String token = st.nextToken();
						String[] result = token.split(":");
						
						try {
						if(result.length >= 2) {
							result[1] = result[1].replaceAll(",", ".");
							
							if(result[0].equals("Total Accesses")) {
								totalAccesses = Long.parseLong(result[1].trim());
							}
							else if(result[0].equals("Total kBytes")) {
								totalkBytes = Double.parseDouble(result[1].trim());
							}
							else if(result[0].equals("CPULoad")) {
								cpuLoad = Double.parseDouble(result[1].trim());
							}
							else if(result[0].equals("Uptime")) {
								uptime = Long.parseLong(result[1].trim());
							}
							else if(result[0].equals("ReqPerSec")) {
								reqPerSec = Double.parseDouble(result[1].trim());
							}
							else if(result[0].equals("BytesPerSec")) {
								bytesPerSec = Double.parseDouble(result[1].trim());
							}
							else if(result[0].equals("BytesPerReq")) {
								bytesPerReq = Double.parseDouble(result[1].trim());
							}	
							else if(result[0].equals("BusyWorkers")) {
								busyWorkers = Double.parseDouble(result[1].trim());
							}	
							else if(result[0].equals("IdleWorkers")) {
								idleWorkers = Double.parseDouble(result[1].trim());
							}
							else if(result[0].equals("Scoreboard")) {
								for(int i=0; i<result[1].length(); i++) {
									
									switch(result[1].charAt(i))
									{
									case '_':
										sbWaitingForConnection++;
										break;

									case 'S':
										sbStartingUp++;
										break;

									case 'R':
										sbReadingRequest++;
										break;

									case 'W':
										sbSendingReply++;
										break;

									case 'K':
										sbKeepAlive++;
										break;

									case 'D':
										sbDnsLookup++;
										break;

									case 'C':
										sbClosingConnection++;
										break;

									case 'L':
										sbLogging++;
										break;

									case 'G':
										sbGracefullyFinishing++;
										break;

									case 'I':
										sbIdleCleanupOfWorker++;
										break;

									case '.':
										sbOpenSlot++;
										break;
									}
									
								}
							}
						}
						} catch(NumberFormatException nfe) {
							status.setMessage("Error converting number:" + result[1] + " for " + result[0]);
							status.setStatusCode(Status.StatusCode.ErrorInternal);
							status.setException(nfe);
							
							if (log.isLoggable(Level.SEVERE))
								log.severe(status.getMessage() + ": " + nfe);
							
							return status;
						}
					}
				} catch (Exception ex) {
					status.setMessage("Parsing the response failed");
					status.setStatusCode(Status.StatusCode.ErrorInternal);
					status.setException(ex);
					
					if (log.isLoggable(Level.SEVERE))
						log.severe(status.getMessage() + ": " + ex);
					
					return status;
				}
				
				// Calculate how utilized the workers are.
				if(idleWorkers > 0)
					workersUtilization = (busyWorkers / (busyWorkers+idleWorkers)) * 100;
				
				connectionCloseDelay = System.nanoTime();
			} // end read response
			
		} catch (HttpException httpe) {
			status.setException(httpe);
			status.setStatusCode(Status.StatusCode.ErrorInfrastructure);
			status.setShortMessage(httpe == null ? "" : httpe.getClass().getSimpleName());
			status.setMessage(httpe == null ? "" : httpe.getMessage());
			if (log.isLoggable(Level.SEVERE))
				log.severe("Requesting URL " + httpMethod.getURI() + " caused exception: " + httpe);
			
		} catch (ConnectException ce) {
			status.setException(ce);
			status.setStatusCode(Status.StatusCode.PartialSuccess);
			status.setShortMessage(ce == null ? "" : ce.getClass().getSimpleName());
			status.setMessage(ce == null ? "" : ce.getMessage());
			
		} catch (IOException ioe) {
			status.setException(ioe);
			status.setStatusCode(Status.StatusCode.ErrorInfrastructure);
			status.setShortMessage(ioe == null ? "" : ioe.getClass().getSimpleName());
			status.setMessage(ioe == null ? "" : ioe.getMessage());
			
			if (log.isLoggable(Level.SEVERE))
				log.severe("Requesting URL " + httpMethod.getURI() + " caused exception: " + ioe);
			
		} catch (IllegalArgumentException iae) {
			status.setException(iae);
			status.setStatusCode(Status.StatusCode.ErrorInfrastructure);
			status.setShortMessage(iae == null ? "" : iae.getClass().getSimpleName());
			status.setMessage(iae == null ? "" : iae.getMessage());
			
			if (log.isLoggable(Level.SEVERE))
				log.severe("Requesting URL " + httpMethod.getURI() + " caused exception: " + iae);	
			
		} finally {
			// always release the connection
			httpMethod.releaseConnection();
			
			if (connectionCloseDelay > 0)
				connectionCloseDelay = System.nanoTime() - connectionCloseDelay;
		}
		
		// calculate and set the measurements
		Collection<MonitorMeasure> measures;
		
		if(status.getStatusCode().getBaseCode() == Status.StatusCode.Success.getBaseCode()) {
			
			setMeasurementValue(env, METRIC_GROUP, MSR_TOTAL_ACCESSES, totalAccesses);
			setMeasurementValue(env, METRIC_GROUP, MSR_TOTAL_MBYTES, (totalkBytes / 1024));
			setMeasurementValue(env, METRIC_GROUP, MSR_CPU_LOAD, cpuLoad);
			setMeasurementValue(env, METRIC_GROUP, MSR_UPTIME, uptime);
			setMeasurementValue(env, METRIC_GROUP, MSR_REQ_PER_SEC, reqPerSec);
			setMeasurementValue(env, METRIC_GROUP, MSR_BYTES_PER_SEC, bytesPerSec / 1024);
			setMeasurementValue(env, METRIC_GROUP, MSR_BYTES_PER_REQ, bytesPerReq / 1024);
			setMeasurementValue(env, METRIC_GROUP, MSR_BUSY_WORKERS, busyWorkers);
			setMeasurementValue(env, METRIC_GROUP, MSR_IDLE_WORKERS, idleWorkers);
			setMeasurementValue(env, METRIC_GROUP, MSR_WORKERS_UTILIZATION, workersUtilization);
			
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_WAITING_FOR_CONNECTION, sbWaitingForConnection);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_STARTING_UP, sbStartingUp);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_READING_REQUEST, sbReadingRequest);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_SENDING_REPLY, sbSendingReply);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_KEEPALIVE, sbKeepAlive);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_DNS_LOOKUP, sbDnsLookup);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_CLOSING_CONNECTION, sbClosingConnection);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_LOGGING, sbLogging);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_GRACEFULLY_FINISHING, sbGracefullyFinishing);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_IDLE_CLEANUP_OF_WORKER, sbIdleCleanupOfWorker);
			setMeasurementValue(env, METRIC_SB_GROUP, MSR_SB_OPEN_SLOT, sbOpenSlot);
		}
		else {
			status.setMessage("Apache page returned invalid status code: " + status.getStatusCode().getBaseCode());
			status.setStatusCode(Status.StatusCode.ErrorInternal);
			
			if (log.isLoggable(Level.SEVERE))
				log.severe(status.getMessage());
		}
		
		return status;
	}

	private Config readConfig(MonitorEnvironment env) {
		Config config = new Config();

		config.protocol = env.getConfigString(CONFIG_PROTOCOL);
		if (config.protocol.equals("http://")) {
			config.port = env.getConfigLong(CONFIG_HTTP_PORT).intValue();
		}
		else {
			config.port = env.getConfigLong(CONFIG_HTTPS_PORT).intValue();
		}
		config.path = env.getConfigString(CONFIG_PATH); 
		config.method = env.getConfigString(CONFIG_METHOD) == null ? "GET" : env.getConfigString(CONFIG_METHOD).toUpperCase();
		config.postData = env.getConfigString(CONFIG_POST_DATA);
		config.httpVersion = env.getConfigString(CONFIG_HTTP_VERSION);
		config.userAgent = env.getConfigString(CONFIG_USER_AGENT);
		config.tagging = env.getConfigBoolean(CONFIG_DT_TAGGING) == null ? false : env.getConfigBoolean(CONFIG_DT_TAGGING);
		config.maxRedirects = env.getConfigLong(CONFIG_MAX_REDIRECTS) == null ? 0 : env.getConfigLong(CONFIG_MAX_REDIRECTS).intValue();
		
		config.serverAuth = env.getConfigBoolean(CONFIG_SERVER_AUTH) == null ? false : env.getConfigBoolean(CONFIG_SERVER_AUTH);
		if (config.serverAuth) {
			config.serverUsername = env.getConfigString(CONFIG_SERVER_USERNAME);
			config.serverPassword = env.getConfigPassword(CONFIG_SERVER_PASSWORD);
		}

		config.useProxy = env.getConfigBoolean(CONFIG_USE_PROXY) == null ? false : env.getConfigBoolean(CONFIG_USE_PROXY);
		if (config.useProxy) {
			config.proxyHost = env.getConfigString(CONFIG_PROXY_HOST);
			config.proxyPort = env.getConfigLong(CONFIG_PROXY_PORT) == null ? 0 : env.getConfigLong(CONFIG_PROXY_PORT).intValue();
		}
		config.proxyAuth = env.getConfigBoolean(CONFIG_PROXY_AUTH) == null ? false : env.getConfigBoolean(CONFIG_PROXY_AUTH);
		if (config.proxyAuth) {
			config.proxyUsername = env.getConfigString(CONFIG_PROXY_USERNAME);
			config.proxyPassword = env.getConfigPassword(CONFIG_PROXY_PASSWORD);
		}
		return config;
	}

	private HttpMethodBase createHttpMethod(Config config, Host host) {
		StringBuilder url = new StringBuilder(config.protocol);
		url.append(host.getAddress()).append(":").append(config.port);
		if (!config.path.startsWith("/"))
			url.append("/");
		url.append(config.path);
		
		HttpMethodBase httpMethod = null;
		if ("GET".equals(config.method)) {
			httpMethod = new GetMethod(url.toString());
		} else if ("HEAD".equals(config.method)) {
			httpMethod = new HeadMethod(url.toString());
		} else if ("POST".equals(config.method)) {
			httpMethod = new PostMethod(url.toString());
			// set the POST data
			if (config.postData != null && config.postData.length() > 0) {
				try {
					StringRequestEntity requestEntity = new StringRequestEntity(config.postData, "application/x-www-form-urlencoded", "UTF-8");
					((PostMethod) httpMethod).setRequestEntity(requestEntity);
				} catch (UnsupportedEncodingException uee) {
					if (log.isLoggable(Level.WARNING))
						log.warning("Encoding POST data failed: " + uee);
				}
			}
		}
		return httpMethod;
	}

	private void setHttpParameters(HttpMethodBase httpMethod, Config config) throws URIException, IllegalStateException {
		HttpVersion httpVersion = HttpVersion.HTTP_1_1;
		try {
			httpVersion = HttpVersion.parse("HTTP/" + config.httpVersion);
			
		} catch (Exception ex) {
			if (log.isLoggable(Level.WARNING))
				log.warning("Parsing httpVersion failed, using default: " + HttpVersion.HTTP_1_1);
		}
		httpClient.getParams().setParameter(HttpClientParams.PROTOCOL_VERSION, httpVersion);
		httpClient.getParams().setParameter(HttpClientParams.USER_AGENT, config.userAgent);
		httpClient.getParams().setParameter(HttpClientParams.MAX_REDIRECTS, config.maxRedirects);
		
		/*
		KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());        
		FileInputStream instream = new FileInputStream(new File("my.keystore")); 
		try {
		    trustStore.load(instream, "nopassword".toCharArray());
		} finally {
		    instream.close();
		}

		SSLSocketFactory socketFactory = new SSLSocketFactory(trustStore);
		Scheme sch = new Scheme("https", socketFactory, 443);
		httpclient.getConnectionManager().getSchemeRegistry().register(sch);
		*/
		
		// set server authentication credentials
		if (config.serverAuth) {
			URI uri = httpMethod.getURI();
			String host = uri.getHost();
			int port = uri.getPort();
			if (port <= 0) {
				Protocol protocol = Protocol.getProtocol(uri.getScheme());
				port = protocol.getDefaultPort();
			}
//			UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(config.serverUsername, config.serverPassword);
			NTCredentials credentials = new NTCredentials(config.serverUsername, config.serverPassword, host, host); 
			httpClient.getState().setCredentials(new AuthScope(host, port, AuthScope.ANY_REALM), credentials);
		}

		// set proxy and credentials
		if (config.useProxy) {
			httpClient.getHostConfiguration().setProxy(config.proxyHost, config.proxyPort);

			if (config.proxyAuth) {
				UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(config.proxyUsername, config.proxyPassword);
				httpClient.getState().setProxyCredentials(new AuthScope(config.proxyHost, config.proxyPort, AuthScope.ANY_REALM), credentials);
			}
		}

		// httpMethod.setRequestHeader("", ""); // TODO trace-tag

		// use a custom retry handler
		HttpMethodRetryHandler retryHandler = new HttpMethodRetryHandler() {
			@Override
            public boolean retryMethod(final HttpMethod method, final IOException exception, int executionCount) {
				// we don't want to retry
				return false;
			}
		};
		httpMethod.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, retryHandler);

		httpMethod.setFollowRedirects((config.maxRedirects > 0 ? true : false));
	}

	private int calculateHeaderSize(Header[] headers) {
		int headerLength = 0;
		for (Header header : headers) {
			headerLength += header.getName().getBytes().length;
			headerLength += header.getValue().getBytes().length;
		}
		return headerLength;
	}
}
