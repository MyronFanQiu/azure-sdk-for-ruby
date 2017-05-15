# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator 1.0.1.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ARM::CDN
  module Models
    #
    # Edge node of CDN service.
    #
    class EdgeNode < MsRestAzure::Resource

      include MsRestAzure

      # @return [Array<IpAddressGroup>] List of ip address groups.
      attr_accessor :ip_address_groups


      #
      # Mapper for EdgeNode class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          required: false,
          serialized_name: 'EdgeNode',
          type: {
            name: 'Composite',
            class_name: 'EdgeNode',
            model_properties: {
              id: {
                required: false,
                read_only: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              name: {
                required: false,
                read_only: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              type: {
                required: false,
                read_only: true,
                serialized_name: 'type',
                type: {
                  name: 'String'
                }
              },
              location: {
                required: true,
                serialized_name: 'location',
                type: {
                  name: 'String'
                }
              },
              tags: {
                required: false,
                serialized_name: 'tags',
                type: {
                  name: 'Dictionary',
                  value: {
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              ip_address_groups: {
                required: true,
                serialized_name: 'properties.ipAddressGroups',
                type: {
                  name: 'Sequence',
                  element: {
                      required: false,
                      serialized_name: 'IpAddressGroupElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'IpAddressGroup'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end