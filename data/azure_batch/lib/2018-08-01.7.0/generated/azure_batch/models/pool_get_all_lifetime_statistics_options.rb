# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # Additional parameters for get_all_lifetime_statistics operation.
    #
    class PoolGetAllLifetimeStatisticsOptions

      include MsRestAzure

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
      # Mapper for PoolGetAllLifetimeStatisticsOptions class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          type: {
            name: 'Composite',
            class_name: 'PoolGetAllLifetimeStatisticsOptions',
            model_properties: {
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
