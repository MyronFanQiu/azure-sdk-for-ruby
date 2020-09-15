# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Compute role against which events will be raised.
    #
    class RoleSinkInfo

      include MsRestAzure

      # @return [String] Compute role ID.
      attr_accessor :role_id


      #
      # Mapper for RoleSinkInfo class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'RoleSinkInfo',
          type: {
            name: 'Composite',
            class_name: 'RoleSinkInfo',
            model_properties: {
              role_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'roleId',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
