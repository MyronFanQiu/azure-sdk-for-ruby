# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # The remote login settings for a compute node.
    #
    #
    class ComputeNodeGetRemoteLoginSettingsResult

      include MsRestAzure

      # @return [String] The IP address used for remote login to the compute
      # node.
      attr_accessor :remote_login_ipaddress

      # @return [Integer] The port used for remote login to the compute node.
      attr_accessor :remote_login_port


      #
      # Mapper for ComputeNodeGetRemoteLoginSettingsResult class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ComputeNodeGetRemoteLoginSettingsResult',
          type: {
            name: 'Composite',
            class_name: 'ComputeNodeGetRemoteLoginSettingsResult',
            model_properties: {
              remote_login_ipaddress: {
                client_side_validation: true,
                required: true,
                serialized_name: 'remoteLoginIPAddress',
                type: {
                  name: 'String'
                }
              },
              remote_login_port: {
                client_side_validation: true,
                required: true,
                serialized_name: 'remoteLoginPort',
                type: {
                  name: 'Number'
                }
              }
            }
          }
        }
      end
    end
  end
end
