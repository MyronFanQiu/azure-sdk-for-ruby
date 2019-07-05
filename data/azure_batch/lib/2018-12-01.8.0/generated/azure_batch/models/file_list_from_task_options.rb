# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # Additional parameters for list_from_task operation.
    #
    class FileListFromTaskOptions

      include MsRestAzure

      # @return [String] An OData $filter clause. For more information on
      # constructing this filter, see
      # https://docs.microsoft.com/en-us/rest/api/batchservice/odata-filters-in-batch#list-task-files.
      attr_accessor :filter

      # @return [Integer] The maximum number of items to return in the
      # response. A maximum of 1000 files can be returned. Default value: 1000
      # .
      attr_accessor :max_results

      # @return [Integer] The maximum time that the server can spend processing
      # the request, in seconds. The default is 30 seconds. Default value: 30 .
      attr_accessor :timeout

      # @return The caller-generated request identity, in the form of a GUID
      # with no decoration such as curly braces, e.g.
      # 9C4D50EE-2D56-4CD3-8152-34347DC9F2B0.
      attr_accessor :client_request_id

      # @return [Boolean] Whether the server should return the
      # client-request-id in the response. Default value: false .
      attr_accessor :return_client_request_id

      # @return [DateTime] The time the request was issued. Client libraries
      # typically set this to the current system clock time; set it explicitly
      # if you are calling the REST API directly.
      attr_accessor :ocp_date


      #
      # Mapper for FileListFromTaskOptions class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          type: {
            name: 'Composite',
            class_name: 'FileListFromTaskOptions',
            model_properties: {
              filter: {
                client_side_validation: true,
                required: false,
                type: {
                  name: 'String'
                }
              },
              max_results: {
                client_side_validation: true,
                required: false,
                default_value: 1000,
                type: {
                  name: 'Number'
                }
              },
              timeout: {
                client_side_validation: true,
                required: false,
                default_value: 30,
                type: {
                  name: 'Number'
                }
              },
              client_request_id: {
                client_side_validation: true,
                required: false,
                type: {
                  name: 'String'
                }
              },
              return_client_request_id: {
                client_side_validation: true,
                required: false,
                default_value: false,
                type: {
                  name: 'Boolean'
                }
              },
              ocp_date: {
                client_side_validation: true,
                required: false,
                type: {
                  name: 'DateTimeRfc1123'
                }
              }
            }
          }
        }
      end
    end
  end
end
