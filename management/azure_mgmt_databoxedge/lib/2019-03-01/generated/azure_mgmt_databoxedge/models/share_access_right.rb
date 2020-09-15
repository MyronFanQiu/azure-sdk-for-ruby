# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_03_01
  module Models
    #
    # Specifies the mapping between this particular user and the type of access
    # he has on shares on this device.
    #
    class ShareAccessRight

      include MsRestAzure

      # @return [String] The share ID.
      attr_accessor :share_id

      # @return [ShareAccessType] Type of access to be allowed on the share for
      # this user. Possible values include: 'Change', 'Read', 'Custom'
      attr_accessor :access_type


      #
      # Mapper for ShareAccessRight class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ShareAccessRight',
          type: {
            name: 'Composite',
            class_name: 'ShareAccessRight',
            model_properties: {
              share_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'shareId',
                type: {
                  name: 'String'
                }
              },
              access_type: {
                client_side_validation: true,
                required: true,
                serialized_name: 'accessType',
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
