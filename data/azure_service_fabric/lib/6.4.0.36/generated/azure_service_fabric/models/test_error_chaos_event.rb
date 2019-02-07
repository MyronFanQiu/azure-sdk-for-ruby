# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_4_0_36
  module Models
    #
    # Describes a Chaos event that gets generated when an unexpected event
    # occurs in the Chaos engine.
    # For example, due to the cluster snapshot being inconsistent, while
    # faulting an entity, Chaos found that the entity was already faulted --
    # which would be an unexpected event.
    #
    class TestErrorChaosEvent < ChaosEvent

      include MsRestAzure


      def initialize
        @Kind = "TestError"
      end

      attr_accessor :Kind

      # @return [String] Describes why TestErrorChaosEvent was generated. For
      # example, Chaos tries to fault a partition but finds that the partition
      # is no longer fault tolerant, then a TestErrorEvent gets generated with
      # the reason stating that the partition is not fault tolerant.
      attr_accessor :reason


      #
      # Mapper for TestErrorChaosEvent class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TestError',
          type: {
            name: 'Composite',
            class_name: 'TestErrorChaosEvent',
            model_properties: {
              time_stamp_utc: {
                client_side_validation: true,
                required: true,
                serialized_name: 'TimeStampUtc',
                type: {
                  name: 'DateTime'
                }
              },
              Kind: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Kind',
                type: {
                  name: 'String'
                }
              },
              reason: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Reason',
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