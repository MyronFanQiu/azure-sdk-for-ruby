# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  #
  # Triggers
  #
  class Triggers
    include MsRestAzure

    #
    # Creates and initializes a new instance of the Triggers class.
    # @param client service class for accessing basic functionality.
    #
    def initialize(client)
      @client = client
    end

    # @return [DataBoxEdgeManagementClient] reference to the DataBoxEdgeManagementClient
    attr_reader :client

    #
    # Lists all the triggers configured in the device.
    #
    # @param device_name [String] The device name.
    # @param resource_group_name [String] The resource group name.
    # @param expand [String] Specify $filter='CustomContextTag eq <tag>' to filter
    # on custom context tag property
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Array<Trigger>] operation results.
    #
    def list_by_data_box_edge_device(device_name, resource_group_name, expand:nil, custom_headers:nil)
      first_page = list_by_data_box_edge_device_as_lazy(device_name, resource_group_name, expand:expand, custom_headers:custom_headers)
      first_page.get_all_items
    end

    #
    # Lists all the triggers configured in the device.
    #
    # @param device_name [String] The device name.
    # @param resource_group_name [String] The resource group name.
    # @param expand [String] Specify $filter='CustomContextTag eq <tag>' to filter
    # on custom context tag property
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_by_data_box_edge_device_with_http_info(device_name, resource_group_name, expand:nil, custom_headers:nil)
      list_by_data_box_edge_device_async(device_name, resource_group_name, expand:expand, custom_headers:custom_headers).value!
    end

    #
    # Lists all the triggers configured in the device.
    #
    # @param device_name [String] The device name.
    # @param resource_group_name [String] The resource group name.
    # @param expand [String] Specify $filter='CustomContextTag eq <tag>' to filter
    # on custom context tag property
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_by_data_box_edge_device_async(device_name, resource_group_name, expand:nil, custom_headers:nil)
      fail ArgumentError, 'device_name is nil' if device_name.nil?
      fail ArgumentError, '@client.subscription_id is nil' if @client.subscription_id.nil?
      fail ArgumentError, 'resource_group_name is nil' if resource_group_name.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?


      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      path_template = 'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataBoxEdge/dataBoxEdgeDevices/{deviceName}/triggers'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'deviceName' => device_name,'subscriptionId' => @client.subscription_id,'resourceGroupName' => resource_group_name},
          query_params: {'api-version' => @client.api_version,'$expand' => expand},
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
          fail MsRestAzure::AzureOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::TriggerList.mapper()
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
    # Get a specific trigger by name.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Trigger] operation results.
    #
    def get(device_name, name, resource_group_name, custom_headers:nil)
      response = get_async(device_name, name, resource_group_name, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Get a specific trigger by name.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def get_with_http_info(device_name, name, resource_group_name, custom_headers:nil)
      get_async(device_name, name, resource_group_name, custom_headers:custom_headers).value!
    end

    #
    # Get a specific trigger by name.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def get_async(device_name, name, resource_group_name, custom_headers:nil)
      fail ArgumentError, 'device_name is nil' if device_name.nil?
      fail ArgumentError, 'name is nil' if name.nil?
      fail ArgumentError, '@client.subscription_id is nil' if @client.subscription_id.nil?
      fail ArgumentError, 'resource_group_name is nil' if resource_group_name.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?


      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      path_template = 'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataBoxEdge/dataBoxEdgeDevices/{deviceName}/triggers/{name}'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'deviceName' => device_name,'name' => name,'subscriptionId' => @client.subscription_id,'resourceGroupName' => resource_group_name},
          query_params: {'api-version' => @client.api_version},
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
          fail MsRestAzure::AzureOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::Trigger.mapper()
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
    # Creates or updates a trigger.
    #
    # @param device_name [String] Creates or updates a trigger
    # @param name [String] The trigger name.
    # @param trigger [Trigger] The trigger.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Trigger] operation results.
    #
    def create_or_update(device_name, name, trigger, resource_group_name, custom_headers:nil)
      response = create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # @param device_name [String] Creates or updates a trigger
    # @param name [String] The trigger name.
    # @param trigger [Trigger] The trigger.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Concurrent::Promise] promise which provides async access to http
    # response.
    #
    def create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:nil)
      # Send request
      promise = begin_create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:custom_headers)

      promise = promise.then do |response|
        # Defining deserialization method.
        deserialize_method = lambda do |parsed_response|
          result_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::Trigger.mapper()
          parsed_response = @client.deserialize(result_mapper, parsed_response)
        end

        # Waiting for response.
        @client.get_long_running_operation_result(response, deserialize_method)
      end

      promise
    end

    #
    # Deletes the trigger on the gateway device.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    def delete(device_name, name, resource_group_name, custom_headers:nil)
      response = delete_async(device_name, name, resource_group_name, custom_headers:custom_headers).value!
      nil
    end

    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Concurrent::Promise] promise which provides async access to http
    # response.
    #
    def delete_async(device_name, name, resource_group_name, custom_headers:nil)
      # Send request
      promise = begin_delete_async(device_name, name, resource_group_name, custom_headers:custom_headers)

      promise = promise.then do |response|
        # Defining deserialization method.
        deserialize_method = lambda do |parsed_response|
        end

        # Waiting for response.
        @client.get_long_running_operation_result(response, deserialize_method)
      end

      promise
    end

    #
    # Creates or updates a trigger.
    #
    # @param device_name [String] Creates or updates a trigger
    # @param name [String] The trigger name.
    # @param trigger [Trigger] The trigger.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Trigger] operation results.
    #
    def begin_create_or_update(device_name, name, trigger, resource_group_name, custom_headers:nil)
      response = begin_create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Creates or updates a trigger.
    #
    # @param device_name [String] Creates or updates a trigger
    # @param name [String] The trigger name.
    # @param trigger [Trigger] The trigger.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def begin_create_or_update_with_http_info(device_name, name, trigger, resource_group_name, custom_headers:nil)
      begin_create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:custom_headers).value!
    end

    #
    # Creates or updates a trigger.
    #
    # @param device_name [String] Creates or updates a trigger
    # @param name [String] The trigger name.
    # @param trigger [Trigger] The trigger.
    # @param resource_group_name [String] The resource group name.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def begin_create_or_update_async(device_name, name, trigger, resource_group_name, custom_headers:nil)
      fail ArgumentError, 'device_name is nil' if device_name.nil?
      fail ArgumentError, 'name is nil' if name.nil?
      fail ArgumentError, 'trigger is nil' if trigger.nil?
      fail ArgumentError, '@client.subscription_id is nil' if @client.subscription_id.nil?
      fail ArgumentError, 'resource_group_name is nil' if resource_group_name.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?


      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?

      # Serialize Request
      request_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::Trigger.mapper()
      request_content = @client.serialize(request_mapper,  trigger)
      request_content = request_content != nil ? JSON.generate(request_content, quirks_mode: true) : nil

      path_template = 'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataBoxEdge/dataBoxEdgeDevices/{deviceName}/triggers/{name}'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'deviceName' => device_name,'name' => name,'subscriptionId' => @client.subscription_id,'resourceGroupName' => resource_group_name},
          query_params: {'api-version' => @client.api_version},
          body: request_content,
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:put, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200 || status_code == 202
          error_model = JSON.load(response_content)
          fail MsRestAzure::AzureOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::Trigger.mapper()
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
    # Deletes the trigger on the gateway device.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    #
    def begin_delete(device_name, name, resource_group_name, custom_headers:nil)
      response = begin_delete_async(device_name, name, resource_group_name, custom_headers:custom_headers).value!
      nil
    end

    #
    # Deletes the trigger on the gateway device.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def begin_delete_with_http_info(device_name, name, resource_group_name, custom_headers:nil)
      begin_delete_async(device_name, name, resource_group_name, custom_headers:custom_headers).value!
    end

    #
    # Deletes the trigger on the gateway device.
    #
    # @param device_name [String] The device name.
    # @param name [String] The trigger name.
    # @param resource_group_name [String] The resource group name.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def begin_delete_async(device_name, name, resource_group_name, custom_headers:nil)
      fail ArgumentError, 'device_name is nil' if device_name.nil?
      fail ArgumentError, 'name is nil' if name.nil?
      fail ArgumentError, '@client.subscription_id is nil' if @client.subscription_id.nil?
      fail ArgumentError, 'resource_group_name is nil' if resource_group_name.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?


      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      path_template = 'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataBoxEdge/dataBoxEdgeDevices/{deviceName}/triggers/{name}'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'deviceName' => device_name,'name' => name,'subscriptionId' => @client.subscription_id,'resourceGroupName' => resource_group_name},
          query_params: {'api-version' => @client.api_version},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:delete, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 200 || status_code == 202 || status_code == 204
          error_model = JSON.load(response_content)
          fail MsRestAzure::AzureOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?

        result
      end

      promise.execute
    end

    #
    # Lists all the triggers configured in the device.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [TriggerList] operation results.
    #
    def list_by_data_box_edge_device_next(next_page_link, custom_headers:nil)
      response = list_by_data_box_edge_device_next_async(next_page_link, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Lists all the triggers configured in the device.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_by_data_box_edge_device_next_with_http_info(next_page_link, custom_headers:nil)
      list_by_data_box_edge_device_next_async(next_page_link, custom_headers:custom_headers).value!
    end

    #
    # Lists all the triggers configured in the device.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_by_data_box_edge_device_next_async(next_page_link, custom_headers:nil)
      fail ArgumentError, 'next_page_link is nil' if next_page_link.nil?


      request_headers = {}
      request_headers['Content-Type'] = 'application/json; charset=utf-8'

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
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
          fail MsRestAzure::AzureOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['x-ms-request-id'] unless http_response['x-ms-request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['x-ms-client-request-id'] unless http_response['x-ms-client-request-id'].nil?
        # Deserialize Response
        if status_code == 200
          begin
            parsed_response = response_content.to_s.empty? ? nil : JSON.load(response_content)
            result_mapper = Azure::DataBoxEdge::Mgmt::V2019_07_01::Models::TriggerList.mapper()
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
    # Lists all the triggers configured in the device.
    #
    # @param device_name [String] The device name.
    # @param resource_group_name [String] The resource group name.
    # @param expand [String] Specify $filter='CustomContextTag eq <tag>' to filter
    # on custom context tag property
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [TriggerList] which provide lazy access to pages of the response.
    #
    def list_by_data_box_edge_device_as_lazy(device_name, resource_group_name, expand:nil, custom_headers:nil)
      response = list_by_data_box_edge_device_async(device_name, resource_group_name, expand:expand, custom_headers:custom_headers).value!
      unless response.nil?
        page = response.body
        page.next_method = Proc.new do |next_page_link|
          list_by_data_box_edge_device_next_async(next_page_link, custom_headers:custom_headers)
        end
        page
      end
    end

  end
end
