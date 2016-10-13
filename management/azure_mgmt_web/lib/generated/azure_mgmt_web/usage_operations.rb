# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ARM::Web
  #
  # Use these APIs to manage Azure Websites resources through the Azure
  # Resource Manager. All task operations conform to the HTTP/1.1 protocol
  # specification and each operation returns an x-ms-request-id header that
  # can be used to obtain information about the request. You must make sure
  # that requests made to these resources are secure. For more information,
  # see <a
  # href="https://msdn.microsoft.com/en-us/library/azure/dn790557.aspx">Authenticating
  # Azure Resource Manager requests.</a>
  #
  class UsageOperations
    include Azure::ARM::Web::Models
    include MsRestAzure

    #
    # Creates and initializes a new instance of the UsageOperations class.
    # @param client service class for accessing basic functionality.
    #
    def initialize(client)
      @client = client
    end

    # @return [WebSiteManagementClient] reference to the WebSiteManagementClient
    attr_reader :client

    #
    # Returns usage records for specified subscription and resource groups
    #
    # @param resource_group_name [String] Name of resource group
    # @param environment_name [String] Environment name
    # @param last_id [String] Last marker that was returned from the batch
    # @param batch_size [Integer] size of the batch to be returned.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Object] operation results.
    #
    def get_usage(resource_group_name, environment_name, last_id, batch_size, custom_headers = nil)
      response = get_usage_async(resource_group_name, environment_name, last_id, batch_size, custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Returns usage records for specified subscription and resource groups
    #
    # @param resource_group_name [String] Name of resource group
    # @param environment_name [String] Environment name
    # @param last_id [String] Last marker that was returned from the batch
    # @param batch_size [Integer] size of the batch to be returned.
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def get_usage_with_http_info(resource_group_name, environment_name, last_id, batch_size, custom_headers = nil)
      get_usage_async(resource_group_name, environment_name, last_id, batch_size, custom_headers).value!
    end

    #
    # Returns usage records for specified subscription and resource groups
    #
    # @param resource_group_name [String] Name of resource group
    # @param environment_name [String] Environment name
    # @param last_id [String] Last marker that was returned from the batch
    # @param batch_size [Integer] size of the batch to be returned.
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def get_usage_async(resource_group_name, environment_name, last_id, batch_size, custom_headers = nil)
      fail ArgumentError, 'resource_group_name is nil' if resource_group_name.nil?
      fail ArgumentError, 'environment_name is nil' if environment_name.nil?
      fail ArgumentError, 'last_id is nil' if last_id.nil?
      fail ArgumentError, 'batch_size is nil' if batch_size.nil?
      fail ArgumentError, '@client.subscription_id is nil' if @client.subscription_id.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?


      request_headers = {}

      # Set Headers
      request_headers['x-ms-client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      path_template = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web.Admin/environments/{environmentName}/usage'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'resourceGroupName' => resource_group_name,'environmentName' => environment_name,'subscriptionId' => @client.subscription_id},
          query_params: {'lastId' => last_id,'batchSize' => batch_size,'api-version' => @client.api_version},
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

        result
      end

      promise.execute
    end

  end
end