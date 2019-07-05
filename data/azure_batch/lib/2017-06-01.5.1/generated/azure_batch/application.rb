# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  #
  # A client for issuing REST requests to the Azure Batch service.
  #
  class Application
    include MsRestAzure

    #
    # Creates and initializes a new instance of the Application class.
    # @param client service class for accessing basic functionality.
    #
    def initialize(client)
      @client = client
    end

    # @return [BatchServiceClient] reference to the BatchServiceClient
    attr_reader :client

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_list_options [ApplicationListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Array<ApplicationSummary>] operation results.
    #
    def list(application_list_options:nil, custom_headers:nil)
      first_page = list_as_lazy(application_list_options:application_list_options, custom_headers:custom_headers)
      first_page.get_all_items
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_list_options [ApplicationListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_with_http_info(application_list_options:nil, custom_headers:nil)
      list_async(application_list_options:application_list_options, custom_headers:custom_headers).value!
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_list_options [ApplicationListOptions] Additional
    # parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_async(application_list_options:nil, custom_headers:nil)
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      max_results = nil
      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless application_list_options.nil?
        max_results = application_list_options.maxResults
      end
      unless application_list_options.nil?
        timeout = application_list_options.timeout
      end
      unless application_list_options.nil?
        client_request_id = application_list_options.client_request_id
      end
      unless application_list_options.nil?
        return_client_request_id = application_list_options.return_client_request_id
      end
      unless application_list_options.nil?
        ocp_date = application_list_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'applications'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          query_params: {'api-version' => @client.api_version,'maxresults' => max_results,'timeout' => timeout},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:get, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::Batch::V2017_06_01_5_1::Models::ApplicationListResult.mapper()
            result.body = @client.deserialize(result_mapper, parsed_response)
          rescue Exception => e
            fail MsRest::DeserializationError.new('Error occurred in deserializing the response', e.message, e.backtrace, result)
          end
        end

        result
      end

      promise.execute
    end

    #
    # Gets information about the specified application.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_id [String] The ID of the application.
    # @param application_get_options [ApplicationGetOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [ApplicationSummary] operation results.
    #
    def get(application_id, application_get_options:nil, custom_headers:nil)
      response = get_async(application_id, application_get_options:application_get_options, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Gets information about the specified application.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_id [String] The ID of the application.
    # @param application_get_options [ApplicationGetOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def get_with_http_info(application_id, application_get_options:nil, custom_headers:nil)
      get_async(application_id, application_get_options:application_get_options, custom_headers:custom_headers).value!
    end

    #
    # Gets information about the specified application.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_id [String] The ID of the application.
    # @param application_get_options [ApplicationGetOptions] Additional parameters
    # for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def get_async(application_id, application_get_options:nil, custom_headers:nil)
      fail ArgumentError, 'application_id is nil' if application_id.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless application_get_options.nil?
        timeout = application_get_options.timeout
      end
      unless application_get_options.nil?
        client_request_id = application_get_options.client_request_id
      end
      unless application_get_options.nil?
        return_client_request_id = application_get_options.return_client_request_id
      end
      unless application_get_options.nil?
        ocp_date = application_get_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'applications/{applicationId}'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'applicationId' => application_id},
          query_params: {'api-version' => @client.api_version,'timeout' => timeout},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:get, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::Batch::V2017_06_01_5_1::Models::ApplicationSummary.mapper()
            result.body = @client.deserialize(result_mapper, parsed_response)
          rescue Exception => e
            fail MsRest::DeserializationError.new('Error occurred in deserializing the response', e.message, e.backtrace, result)
          end
        end

        result
      end

      promise.execute
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param application_list_next_options [ApplicationListNextOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [ApplicationListResult] operation results.
    #
    def list_next(next_page_link, application_list_next_options:nil, custom_headers:nil)
      response = list_next_async(next_page_link, application_list_next_options:application_list_next_options, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param application_list_next_options [ApplicationListNextOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_next_with_http_info(next_page_link, application_list_next_options:nil, custom_headers:nil)
      list_next_async(next_page_link, application_list_next_options:application_list_next_options, custom_headers:custom_headers).value!
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param application_list_next_options [ApplicationListNextOptions] Additional
    # parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_next_async(next_page_link, application_list_next_options:nil, custom_headers:nil)
      fail ArgumentError, 'next_page_link is nil' if next_page_link.nil?

      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless application_list_next_options.nil?
        client_request_id = application_list_next_options.client_request_id
      end
      unless application_list_next_options.nil?
        return_client_request_id = application_list_next_options.return_client_request_id
      end
      unless application_list_next_options.nil?
        ocp_date = application_list_next_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = '{nextLink}'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          skip_encoding_path_params: {'nextLink' => next_page_link},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:get, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::Batch::V2017_06_01_5_1::Models::ApplicationListResult.mapper()
            result.body = @client.deserialize(result_mapper, parsed_response)
          rescue Exception => e
            fail MsRest::DeserializationError.new('Error occurred in deserializing the response', e.message, e.backtrace, result)
          end
        end

        result
      end

      promise.execute
    end

    #
    # Lists all of the applications available in the specified account.
    #
    # This operation returns only applications and versions that are available for
    # use on compute nodes; that is, that can be used in an application package
    # reference. For administrator information about applications and versions that
    # are not yet available to compute nodes, use the Azure portal or the Azure
    # Resource Manager API.
    #
    # @param application_list_options [ApplicationListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [ApplicationListResult] which provide lazy access to pages of the
    # response.
    #
    def list_as_lazy(application_list_options:nil, custom_headers:nil)
      response = list_async(application_list_options:application_list_options, custom_headers:custom_headers).value!
      unless response.nil?
        page = response.body
        page.next_method = Proc.new do |next_page_link|
          application_list_next_options = application_list_options
          list_next_async(next_page_link, application_list_next_options:application_list_next_options, custom_headers:custom_headers)
        end
        page
      end
    end

  end
end
