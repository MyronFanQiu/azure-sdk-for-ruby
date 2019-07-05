# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  #
  # A client for issuing REST requests to the Azure Batch service.
  #
  class CertificateOperations
    include MsRestAzure

    #
    # Creates and initializes a new instance of the CertificateOperations class.
    # @param client service class for accessing basic functionality.
    #
    def initialize(client)
      @client = client
    end

    # @return [BatchServiceClient] reference to the BatchServiceClient
    attr_reader :client

    #
    # Adds a certificate to the specified account.
    #
    # @param certificate [CertificateAddParameter] The certificate to be added.
    # @param certificate_add_options [CertificateAddOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    #
    def add(certificate, certificate_add_options:nil, custom_headers:nil)
      response = add_async(certificate, certificate_add_options:certificate_add_options, custom_headers:custom_headers).value!
      nil
    end

    #
    # Adds a certificate to the specified account.
    #
    # @param certificate [CertificateAddParameter] The certificate to be added.
    # @param certificate_add_options [CertificateAddOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def add_with_http_info(certificate, certificate_add_options:nil, custom_headers:nil)
      add_async(certificate, certificate_add_options:certificate_add_options, custom_headers:custom_headers).value!
    end

    #
    # Adds a certificate to the specified account.
    #
    # @param certificate [CertificateAddParameter] The certificate to be added.
    # @param certificate_add_options [CertificateAddOptions] Additional parameters
    # for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def add_async(certificate, certificate_add_options:nil, custom_headers:nil)
      fail ArgumentError, 'certificate is nil' if certificate.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_add_options.nil?
        timeout = certificate_add_options.timeout
      end
      unless certificate_add_options.nil?
        client_request_id = certificate_add_options.client_request_id
      end
      unless certificate_add_options.nil?
        return_client_request_id = certificate_add_options.return_client_request_id
      end
      unless certificate_add_options.nil?
        ocp_date = certificate_add_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?

      # Serialize Request
      request_mapper = Azure::Batch::V2017_09_01_6_0::Models::CertificateAddParameter.mapper()
      request_content = @client.serialize(request_mapper,  certificate)
      request_content = request_content != nil ? JSON.generate(request_content, quirks_mode: true) : nil

      path_template = 'certificates'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          query_params: {'api-version' => @client.api_version,'timeout' => timeout},
          body: request_content,
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:post, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 201
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?

        result
      end

      promise.execute
    end

    #
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param certificate_list_options [CertificateListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Array<Certificate>] operation results.
    #
    def list(certificate_list_options:nil, custom_headers:nil)
      first_page = list_as_lazy(certificate_list_options:certificate_list_options, custom_headers:custom_headers)
      first_page.get_all_items
    end

    #
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param certificate_list_options [CertificateListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_with_http_info(certificate_list_options:nil, custom_headers:nil)
      list_async(certificate_list_options:certificate_list_options, custom_headers:custom_headers).value!
    end

    #
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param certificate_list_options [CertificateListOptions] Additional
    # parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_async(certificate_list_options:nil, custom_headers:nil)
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      filter = nil
      select = nil
      max_results = nil
      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_list_options.nil?
        filter = certificate_list_options.filter
      end
      unless certificate_list_options.nil?
        select = certificate_list_options.select
      end
      unless certificate_list_options.nil?
        max_results = certificate_list_options.maxResults
      end
      unless certificate_list_options.nil?
        timeout = certificate_list_options.timeout
      end
      unless certificate_list_options.nil?
        client_request_id = certificate_list_options.client_request_id
      end
      unless certificate_list_options.nil?
        return_client_request_id = certificate_list_options.return_client_request_id
      end
      unless certificate_list_options.nil?
        ocp_date = certificate_list_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'certificates'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          query_params: {'api-version' => @client.api_version,'$filter' => filter,'$select' => select,'maxresults' => max_results,'timeout' => timeout},
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
            result_mapper = Azure::Batch::V2017_09_01_6_0::Models::CertificateListResult.mapper()
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
    # Cancels a failed deletion of a certificate from the specified account.
    #
    # If you try to delete a certificate that is being used by a pool or compute
    # node, the status of the certificate changes to deleteFailed. If you decide
    # that you want to continue using the certificate, you can use this operation
    # to set the status of the certificate back to active. If you intend to delete
    # the certificate, you do not need to run this operation after the deletion
    # failed. You must make sure that the certificate is not being used by any
    # resources, and then you can try again to delete the certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate being deleted.
    # @param certificate_cancel_deletion_options [CertificateCancelDeletionOptions]
    # Additional parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    #
    def cancel_deletion(thumbprint_algorithm, thumbprint, certificate_cancel_deletion_options:nil, custom_headers:nil)
      response = cancel_deletion_async(thumbprint_algorithm, thumbprint, certificate_cancel_deletion_options:certificate_cancel_deletion_options, custom_headers:custom_headers).value!
      nil
    end

    #
    # Cancels a failed deletion of a certificate from the specified account.
    #
    # If you try to delete a certificate that is being used by a pool or compute
    # node, the status of the certificate changes to deleteFailed. If you decide
    # that you want to continue using the certificate, you can use this operation
    # to set the status of the certificate back to active. If you intend to delete
    # the certificate, you do not need to run this operation after the deletion
    # failed. You must make sure that the certificate is not being used by any
    # resources, and then you can try again to delete the certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate being deleted.
    # @param certificate_cancel_deletion_options [CertificateCancelDeletionOptions]
    # Additional parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def cancel_deletion_with_http_info(thumbprint_algorithm, thumbprint, certificate_cancel_deletion_options:nil, custom_headers:nil)
      cancel_deletion_async(thumbprint_algorithm, thumbprint, certificate_cancel_deletion_options:certificate_cancel_deletion_options, custom_headers:custom_headers).value!
    end

    #
    # Cancels a failed deletion of a certificate from the specified account.
    #
    # If you try to delete a certificate that is being used by a pool or compute
    # node, the status of the certificate changes to deleteFailed. If you decide
    # that you want to continue using the certificate, you can use this operation
    # to set the status of the certificate back to active. If you intend to delete
    # the certificate, you do not need to run this operation after the deletion
    # failed. You must make sure that the certificate is not being used by any
    # resources, and then you can try again to delete the certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate being deleted.
    # @param certificate_cancel_deletion_options [CertificateCancelDeletionOptions]
    # Additional parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def cancel_deletion_async(thumbprint_algorithm, thumbprint, certificate_cancel_deletion_options:nil, custom_headers:nil)
      fail ArgumentError, 'thumbprint_algorithm is nil' if thumbprint_algorithm.nil?
      fail ArgumentError, 'thumbprint is nil' if thumbprint.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_cancel_deletion_options.nil?
        timeout = certificate_cancel_deletion_options.timeout
      end
      unless certificate_cancel_deletion_options.nil?
        client_request_id = certificate_cancel_deletion_options.client_request_id
      end
      unless certificate_cancel_deletion_options.nil?
        return_client_request_id = certificate_cancel_deletion_options.return_client_request_id
      end
      unless certificate_cancel_deletion_options.nil?
        ocp_date = certificate_cancel_deletion_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'certificates(thumbprintAlgorithm={thumbprintAlgorithm},thumbprint={thumbprint})/canceldelete'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'thumbprintAlgorithm' => thumbprint_algorithm,'thumbprint' => thumbprint},
          query_params: {'api-version' => @client.api_version,'timeout' => timeout},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:post, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 204
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?

        result
      end

      promise.execute
    end

    #
    # Deletes a certificate from the specified account.
    #
    # You cannot delete a certificate if a resource (pool or compute node) is using
    # it. Before you can delete a certificate, you must therefore make sure that
    # the certificate is not associated with any existing pools, the certificate is
    # not installed on any compute nodes (even if you remove a certificate from a
    # pool, it is not removed from existing compute nodes in that pool until they
    # restart), and no running tasks depend on the certificate. If you try to
    # delete a certificate that is in use, the deletion fails. The certificate
    # status changes to deleteFailed. You can use Cancel Delete Certificate to set
    # the status back to active if you decide that you want to continue using the
    # certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to be deleted.
    # @param certificate_delete_options [CertificateDeleteOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    #
    def delete(thumbprint_algorithm, thumbprint, certificate_delete_options:nil, custom_headers:nil)
      response = delete_async(thumbprint_algorithm, thumbprint, certificate_delete_options:certificate_delete_options, custom_headers:custom_headers).value!
      nil
    end

    #
    # Deletes a certificate from the specified account.
    #
    # You cannot delete a certificate if a resource (pool or compute node) is using
    # it. Before you can delete a certificate, you must therefore make sure that
    # the certificate is not associated with any existing pools, the certificate is
    # not installed on any compute nodes (even if you remove a certificate from a
    # pool, it is not removed from existing compute nodes in that pool until they
    # restart), and no running tasks depend on the certificate. If you try to
    # delete a certificate that is in use, the deletion fails. The certificate
    # status changes to deleteFailed. You can use Cancel Delete Certificate to set
    # the status back to active if you decide that you want to continue using the
    # certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to be deleted.
    # @param certificate_delete_options [CertificateDeleteOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def delete_with_http_info(thumbprint_algorithm, thumbprint, certificate_delete_options:nil, custom_headers:nil)
      delete_async(thumbprint_algorithm, thumbprint, certificate_delete_options:certificate_delete_options, custom_headers:custom_headers).value!
    end

    #
    # Deletes a certificate from the specified account.
    #
    # You cannot delete a certificate if a resource (pool or compute node) is using
    # it. Before you can delete a certificate, you must therefore make sure that
    # the certificate is not associated with any existing pools, the certificate is
    # not installed on any compute nodes (even if you remove a certificate from a
    # pool, it is not removed from existing compute nodes in that pool until they
    # restart), and no running tasks depend on the certificate. If you try to
    # delete a certificate that is in use, the deletion fails. The certificate
    # status changes to deleteFailed. You can use Cancel Delete Certificate to set
    # the status back to active if you decide that you want to continue using the
    # certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to be deleted.
    # @param certificate_delete_options [CertificateDeleteOptions] Additional
    # parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def delete_async(thumbprint_algorithm, thumbprint, certificate_delete_options:nil, custom_headers:nil)
      fail ArgumentError, 'thumbprint_algorithm is nil' if thumbprint_algorithm.nil?
      fail ArgumentError, 'thumbprint is nil' if thumbprint.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_delete_options.nil?
        timeout = certificate_delete_options.timeout
      end
      unless certificate_delete_options.nil?
        client_request_id = certificate_delete_options.client_request_id
      end
      unless certificate_delete_options.nil?
        return_client_request_id = certificate_delete_options.return_client_request_id
      end
      unless certificate_delete_options.nil?
        ocp_date = certificate_delete_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'certificates(thumbprintAlgorithm={thumbprintAlgorithm},thumbprint={thumbprint})'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'thumbprintAlgorithm' => thumbprint_algorithm,'thumbprint' => thumbprint},
          query_params: {'api-version' => @client.api_version,'timeout' => timeout},
          headers: request_headers.merge(custom_headers || {}),
          base_url: request_url
      }
      promise = @client.make_request_async(:delete, path_template, options)

      promise = promise.then do |result|
        http_response = result.response
        status_code = http_response.status
        response_content = http_response.body
        unless status_code == 202
          error_model = JSON.load(response_content)
          fail MsRest::HttpOperationError.new(result.request, http_response, error_model)
        end

        result.request_id = http_response['request-id'] unless http_response['request-id'].nil?
        result.correlation_request_id = http_response['x-ms-correlation-request-id'] unless http_response['x-ms-correlation-request-id'].nil?
        result.client_request_id = http_response['client-request-id'] unless http_response['client-request-id'].nil?

        result
      end

      promise.execute
    end

    #
    # Gets information about the specified certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to get.
    # @param certificate_get_options [CertificateGetOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [Certificate] operation results.
    #
    def get(thumbprint_algorithm, thumbprint, certificate_get_options:nil, custom_headers:nil)
      response = get_async(thumbprint_algorithm, thumbprint, certificate_get_options:certificate_get_options, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Gets information about the specified certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to get.
    # @param certificate_get_options [CertificateGetOptions] Additional parameters
    # for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def get_with_http_info(thumbprint_algorithm, thumbprint, certificate_get_options:nil, custom_headers:nil)
      get_async(thumbprint_algorithm, thumbprint, certificate_get_options:certificate_get_options, custom_headers:custom_headers).value!
    end

    #
    # Gets information about the specified certificate.
    #
    # @param thumbprint_algorithm [String] The algorithm used to derive the
    # thumbprint parameter. This must be sha1.
    # @param thumbprint [String] The thumbprint of the certificate to get.
    # @param certificate_get_options [CertificateGetOptions] Additional parameters
    # for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def get_async(thumbprint_algorithm, thumbprint, certificate_get_options:nil, custom_headers:nil)
      fail ArgumentError, 'thumbprint_algorithm is nil' if thumbprint_algorithm.nil?
      fail ArgumentError, 'thumbprint is nil' if thumbprint.nil?
      fail ArgumentError, '@client.api_version is nil' if @client.api_version.nil?

      select = nil
      timeout = nil
      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_get_options.nil?
        select = certificate_get_options.select
      end
      unless certificate_get_options.nil?
        timeout = certificate_get_options.timeout
      end
      unless certificate_get_options.nil?
        client_request_id = certificate_get_options.client_request_id
      end
      unless certificate_get_options.nil?
        return_client_request_id = certificate_get_options.return_client_request_id
      end
      unless certificate_get_options.nil?
        ocp_date = certificate_get_options.ocp_date
      end

      request_headers = {}
      request_headers['Content-Type'] = 'application/json; odata=minimalmetadata; charset=utf-8'

      # Set Headers
      request_headers['client-request-id'] = SecureRandom.uuid
      request_headers['accept-language'] = @client.accept_language unless @client.accept_language.nil?
      request_headers['client-request-id'] = client_request_id.to_s unless client_request_id.to_s.nil?
      request_headers['return-client-request-id'] = return_client_request_id.to_s unless return_client_request_id.to_s.nil?
      request_headers['ocp-date'] = ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT') unless ocp_date.strftime('%a, %d %b %Y %H:%M:%S GMT').nil?
      path_template = 'certificates(thumbprintAlgorithm={thumbprintAlgorithm},thumbprint={thumbprint})'

      request_url = @base_url || @client.base_url

      options = {
          middlewares: [[MsRest::RetryPolicyMiddleware, times: 3, retry: 0.02], [:cookie_jar]],
          path_params: {'thumbprintAlgorithm' => thumbprint_algorithm,'thumbprint' => thumbprint},
          query_params: {'api-version' => @client.api_version,'$select' => select,'timeout' => timeout},
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
            result_mapper = Azure::Batch::V2017_09_01_6_0::Models::Certificate.mapper()
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
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param certificate_list_next_options [CertificateListNextOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [CertificateListResult] operation results.
    #
    def list_next(next_page_link, certificate_list_next_options:nil, custom_headers:nil)
      response = list_next_async(next_page_link, certificate_list_next_options:certificate_list_next_options, custom_headers:custom_headers).value!
      response.body unless response.nil?
    end

    #
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param certificate_list_next_options [CertificateListNextOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [MsRestAzure::AzureOperationResponse] HTTP response information.
    #
    def list_next_with_http_info(next_page_link, certificate_list_next_options:nil, custom_headers:nil)
      list_next_async(next_page_link, certificate_list_next_options:certificate_list_next_options, custom_headers:custom_headers).value!
    end

    #
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param next_page_link [String] The NextLink from the previous successful call
    # to List operation.
    # @param certificate_list_next_options [CertificateListNextOptions] Additional
    # parameters for the operation
    # @param [Hash{String => String}] A hash of custom headers that will be added
    # to the HTTP request.
    #
    # @return [Concurrent::Promise] Promise object which holds the HTTP response.
    #
    def list_next_async(next_page_link, certificate_list_next_options:nil, custom_headers:nil)
      fail ArgumentError, 'next_page_link is nil' if next_page_link.nil?

      client_request_id = nil
      return_client_request_id = nil
      ocp_date = nil
      unless certificate_list_next_options.nil?
        client_request_id = certificate_list_next_options.client_request_id
      end
      unless certificate_list_next_options.nil?
        return_client_request_id = certificate_list_next_options.return_client_request_id
      end
      unless certificate_list_next_options.nil?
        ocp_date = certificate_list_next_options.ocp_date
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
            result_mapper = Azure::Batch::V2017_09_01_6_0::Models::CertificateListResult.mapper()
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
    # Lists all of the certificates that have been added to the specified account.
    #
    # @param certificate_list_options [CertificateListOptions] Additional
    # parameters for the operation
    # @param custom_headers [Hash{String => String}] A hash of custom headers that
    # will be added to the HTTP request.
    #
    # @return [CertificateListResult] which provide lazy access to pages of the
    # response.
    #
    def list_as_lazy(certificate_list_options:nil, custom_headers:nil)
      response = list_async(certificate_list_options:certificate_list_options, custom_headers:custom_headers).value!
      unless response.nil?
        page = response.body
        page.next_method = Proc.new do |next_page_link|
          certificate_list_next_options = certificate_list_options
          list_next_async(next_page_link, certificate_list_next_options:certificate_list_next_options, custom_headers:custom_headers)
        end
        page
      end
    end

  end
end
